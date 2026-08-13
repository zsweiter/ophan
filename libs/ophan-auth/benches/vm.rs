use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::fmt;

//
// DSL
//
// allow if (
//     subject.role == "admin"
//     && request.method == "GET"
// );
//
// Bytecode
//
// 00 LOAD_ROLE
// 01 PUSH_STR "admin"
// 02 EQ
// 03 JMP_FALSE 10
//
// 04 LOAD_METHOD
// 05 PUSH_STR "GET"
// 06 EQ
// 07 JMP_FALSE 10
//
// 08 PUSH_BOOL true
// 09 RETURN
//
// 10 PUSH_BOOL false
// 11 RETURN
//

#[derive(Clone, PartialEq)]
pub enum Value {
    String(String),
    Bool(bool),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::String(v) => write!(f, "\"{}\"", v),
            Value::Bool(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Debug)]
pub enum OpCode {
    LoadRole,
    LoadMethod,

    PushString(String),
    PushBool(bool),

    Eq,

    Jump(usize),
    JumpIfFalse(usize),

    Print,

    Return,
}

pub struct Context {
    pub role: String,
    pub method: String,
}

pub struct Vm {
    pc: usize,
    stack: Vec<Value>,
    debug: bool,
}

impl Vm {
    pub fn new(debug: bool) -> Self {
        Self { pc: 0, stack: Vec::new(), debug }
    }

    pub fn execute(&mut self, code: &[OpCode], ctx: &Context) -> bool {
        self.pc = 0;
        self.stack.clear();

        loop {
            if self.debug {
                println!("[pc={:02}] {:?}", self.pc, code[self.pc]);
            }

            match &code[self.pc] {
                OpCode::LoadRole => {
                    self.stack.push(Value::String(ctx.role.clone()));
                },

                OpCode::LoadMethod => {
                    self.stack.push(Value::String(ctx.method.clone()));
                },

                OpCode::PushString(v) => {
                    self.stack.push(Value::String(v.clone()));
                },

                OpCode::PushBool(v) => {
                    self.stack.push(Value::Bool(*v));
                },

                OpCode::Eq => {
                    let rhs = self.stack.pop().unwrap();
                    let lhs = self.stack.pop().unwrap();

                    self.stack.push(Value::Bool(lhs == rhs));
                },

                OpCode::Jump(target) => {
                    self.pc = *target;
                    continue;
                },

                OpCode::JumpIfFalse(target) => {
                    let cond = self.stack.pop().unwrap();

                    match cond {
                        Value::Bool(false) => {
                            self.pc = *target;
                            continue;
                        },
                        Value::Bool(true) => {},
                        _ => panic!("expected bool"),
                    }
                },

                OpCode::Print => {
                    println!("STACK => {:?}", self.stack);
                },

                OpCode::Return => {
                    return match self.stack.pop().unwrap() {
                        Value::Bool(v) => v,
                        _ => panic!("expected bool"),
                    };
                },
            }

            if self.debug {
                println!("       stack = {:?}\n", self.stack);
            }

            self.pc += 1;
        }
    }
}

fn compile() -> Vec<OpCode> {
    vec![
        // subject.role == "admin"
        OpCode::LoadRole,
        OpCode::PushString("admin".into()),
        OpCode::Eq,
        OpCode::Print,
        OpCode::JumpIfFalse(10),
        // request.method == "GET"
        OpCode::LoadMethod,
        OpCode::PushString("GET".into()),
        OpCode::Eq,
        OpCode::Print,
        OpCode::JumpIfFalse(10),
        // allow
        OpCode::PushBool(true),
        OpCode::Return,
        // deny
        OpCode::PushBool(false),
        OpCode::Return,
    ]
}

fn bench_policy_vm(c: &mut Criterion) {
    let code = compile();

    let ctx = Context { role: "admin".into(), method: "GET".into() };

    let mut vm = Vm::new(false);

    c.bench_function("policy_vm", |b| {
        b.iter(|| {
            black_box(vm.execute(black_box(&code), black_box(&ctx)));
        });
    });
}

criterion_group!(benches, bench_policy_vm);
criterion_main!(benches);
