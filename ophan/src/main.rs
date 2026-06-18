use ophan::errors::ExitCode;

fn main() -> ExitCode {
    if let Err(code) = ophan::main_entry() {
        return code;
    }

    ExitCode::Ok
}
