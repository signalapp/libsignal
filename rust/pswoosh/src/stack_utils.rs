use std::thread;

pub const STACK_SIZE: usize = 32 * 1024 * 1024; // 32 MB

pub fn run_with_large_stack<F>(test_fn: F, test_name: &str)
where
    F: FnOnce() + Send + 'static,
{
    let builder = thread::Builder::new().stack_size(STACK_SIZE);
    let test_name = String::from(test_name);
    let handler = builder
        .spawn(move || {
            println!("Running {} with {}MB stack", test_name, STACK_SIZE / (1024 * 1024));
            test_fn();
        })
        .unwrap();

    handler.join().unwrap();
}