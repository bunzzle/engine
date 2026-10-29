use std::cell::RefCell;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Wake, Waker};
use std::thread::{self, ThreadId};

use crate::driver::{Driver, Unpark};
use crate::time::Instant;

type LocalFuture = Pin<Box<dyn Future<Output = ()>>>;

thread_local! {
    static CURRENT: RefCell<Option<Rc<Inner>>> = const { RefCell::new(None) };
}

struct Shared {
    ready: Mutex<VecDeque<usize>>,
    unpark: Arc<dyn Unpark>,
    owner: ThreadId,
}

struct TaskWaker {
    id: usize,
    queued: AtomicBool,
    shared: Arc<Shared>,
}

impl Wake for TaskWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if self.queued.swap(true, Ordering::AcqRel) {
            return;
        }
        self.shared
            .ready
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(self.id);
        if thread::current().id() != self.shared.owner {
            self.shared.unpark.unpark();
        }
    }
}

struct Task {
    future: LocalFuture,
    waker: Arc<TaskWaker>,
}

#[derive(Default)]
struct Timers {
    heap: BinaryHeap<Reverse<(Instant, u64)>>,
    wakers: HashMap<u64, Waker>,
    next_key: u64,
}

pub(crate) struct Inner {
    driver: Rc<dyn Driver>,
    shared: Arc<Shared>,
    tasks: RefCell<Vec<Option<Task>>>,
    free: RefCell<Vec<usize>>,
    timers: RefCell<Timers>,
}

impl Inner {
    pub(crate) fn new(driver: Rc<dyn Driver>) -> Rc<Self> {
        let shared = Arc::new(Shared {
            ready: Mutex::new(VecDeque::new()),
            unpark: driver.unparker(),
            owner: thread::current().id(),
        });
        Rc::new(Self {
            driver,
            shared,
            tasks: RefCell::new(Vec::new()),
            free: RefCell::new(Vec::new()),
            timers: RefCell::new(Timers::default()),
        })
    }

    fn spawn_local(&self, future: LocalFuture) {
        let reused = self.free.borrow_mut().pop();
        let id = reused.unwrap_or_else(|| {
            let mut tasks = self.tasks.borrow_mut();
            tasks.push(None);
            tasks.len() - 1
        });
        let waker = Arc::new(TaskWaker {
            id,
            queued: AtomicBool::new(false),
            shared: Arc::clone(&self.shared),
        });
        self.tasks.borrow_mut()[id] = Some(Task {
            future,
            waker: Arc::clone(&waker),
        });
        waker.wake_by_ref();
    }

    pub(crate) fn run_ready(&self) {
        let batch: Vec<usize> = self
            .shared
            .ready
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
            .collect();
        for id in batch {
            let task = self.tasks.borrow_mut().get_mut(id).and_then(Option::take);
            let Some(mut task) = task else {
                continue;
            };
            task.waker.queued.store(false, Ordering::Release);
            let waker = Waker::from(Arc::clone(&task.waker));
            let mut cx = Context::from_waker(&waker);
            if task.future.as_mut().poll(&mut cx).is_ready() {
                self.free.borrow_mut().push(id);
            } else {
                self.tasks.borrow_mut()[id] = Some(task);
            }
        }
    }

    pub(crate) fn has_ready(&self) -> bool {
        !self
            .shared
            .ready
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_empty()
    }

    pub(crate) fn register_timer(&self, deadline: Instant, key: Option<u64>, waker: &Waker) -> u64 {
        let mut timers = self.timers.borrow_mut();
        if let Some(key) = key
            && let Some(existing) = timers.wakers.get_mut(&key)
        {
            existing.clone_from(waker);
            return key;
        }
        let key = timers.next_key;
        timers.next_key += 1;
        timers.heap.push(Reverse((deadline, key)));
        timers.wakers.insert(key, waker.clone());
        key
    }

    pub(crate) fn cancel_timer(&self, key: u64) {
        self.timers.borrow_mut().wakers.remove(&key);
    }

    pub(crate) fn fire_timers(&self) {
        let now = self.driver.now();
        let mut due = Vec::new();
        {
            let mut timers = self.timers.borrow_mut();
            while let Some(Reverse((deadline, key))) = timers.heap.peek().copied() {
                if deadline > now {
                    break;
                }
                timers.heap.pop();
                if let Some(waker) = timers.wakers.remove(&key) {
                    due.push(waker);
                }
            }
        }
        for waker in due {
            waker.wake();
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        let mut timers = self.timers.borrow_mut();
        while let Some(Reverse((deadline, key))) = timers.heap.peek().copied() {
            if timers.wakers.contains_key(&key) {
                return Some(deadline);
            }
            timers.heap.pop();
        }
        None
    }

    pub(crate) fn now(&self) -> Instant {
        self.driver.now()
    }

    pub(crate) fn wall_ms(&self) -> u64 {
        self.driver.wall_ms()
    }
}

pub(crate) fn current() -> Rc<Inner> {
    try_current().expect("called outside of a runtime")
}

pub(crate) fn try_current() -> Option<Rc<Inner>> {
    CURRENT.with(|current| current.borrow().clone())
}

pub(crate) fn driver() -> Rc<dyn Driver> {
    Rc::clone(&current().driver)
}

pub(crate) struct Enter {
    previous: Option<Rc<Inner>>,
}

impl Enter {
    fn new(inner: Rc<Inner>) -> Self {
        CURRENT.with(|current| {
            let mut current = current.borrow_mut();
            assert!(
                current.is_none(),
                "a runtime is already running on this thread"
            );
            *current = Some(inner);
        });
        Self { previous: None }
    }

    pub(crate) fn swap(inner: Rc<Inner>) -> Self {
        let previous = CURRENT.with(|current| current.borrow_mut().replace(inner));
        Self { previous }
    }
}

impl Drop for Enter {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CURRENT.with(|current| *current.borrow_mut() = previous);
    }
}

pub struct Runtime {
    inner: Rc<Inner>,
}

impl Runtime {
    pub fn new(driver: Rc<dyn Driver>) -> Self {
        Self {
            inner: Inner::new(driver),
        }
    }

    pub fn block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let _enter = Enter::new(Rc::clone(&self.inner));
        let slot = Rc::new(RefCell::new(None));
        let out = Rc::clone(&slot);
        self.inner.spawn_local(Box::pin(async move {
            let value = future.await;
            *out.borrow_mut() = Some(value);
        }));
        loop {
            self.inner.fire_timers();
            self.inner.run_ready();
            if let Some(value) = slot.borrow_mut().take() {
                return value;
            }
            if self.inner.has_ready() {
                continue;
            }
            let deadline = self.inner.next_deadline();
            self.inner.driver.park(deadline);
        }
    }
}

struct JoinState<T> {
    value: Option<T>,
    waker: Option<Waker>,
}

pub struct JoinHandle<T> {
    state: Rc<RefCell<JoinState<T>>>,
}

impl<T> Future for JoinHandle<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<T> {
        let mut state = self.state.borrow_mut();
        if let Some(value) = state.value.take() {
            return Poll::Ready(value);
        }
        state.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

pub fn spawn<F>(future: F) -> JoinHandle<F::Output>
where
    F: Future + 'static,
    F::Output: 'static,
{
    let state = Rc::new(RefCell::new(JoinState {
        value: None,
        waker: None,
    }));
    let task_state = Rc::clone(&state);
    current().spawn_local(Box::pin(async move {
        let value = future.await;
        let waker = {
            let mut state = task_state.borrow_mut();
            state.value = Some(value);
            state.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }));
    JoinHandle { state }
}

pub fn yield_now() -> YieldNow {
    YieldNow { yielded: false }
}

pub struct YieldNow {
    yielded: bool,
}

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
