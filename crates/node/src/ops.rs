use std::fmt::Write;
use std::rc::Rc;

use admin::{Admin, Code, Handler, Reply, Request};
use rt::UnixListener;
use sched::{Node, Transport};

struct Ops<T: Transport + 'static> {
    node: Node<T>,
    cores: u16,
}

impl<T: Transport + 'static> Handler for Ops<T> {
    fn handle(&self, request: Request) -> impl Future<Output = Reply> {
        let reply = match request {
            Request::Status => {
                let mut text = String::new();
                let _ = writeln!(text, "node {}", self.node.settings().node);
                let _ = writeln!(text, "cores {}", self.cores);
                let _ = writeln!(text, "control version {}", self.node.table().version());
                Reply::new(Code::Ok, text)
            }
        };
        std::future::ready(reply)
    }
}

pub(crate) fn serve<T: Transport + 'static>(
    listener: Option<UnixListener>,
    node: &Node<T>,
    cores: u16,
    engine: u32,
) -> Option<Admin> {
    let listener = listener?;
    let ops = Ops {
        node: node.clone(),
        cores,
    };
    Some(admin::serve(listener, vec![engine, 0], Rc::new(ops)))
}
