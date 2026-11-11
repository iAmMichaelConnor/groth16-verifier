use std::time::Instant;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let input = std::fs::read(&args[1]).unwrap();
    let expected = std::fs::read(&args[2]).unwrap();
    let setup = Instant::now();
    groth16_hint_runtime_tail_kernel::full::prepare();
    println!("setup_seconds={}", setup.elapsed().as_secs_f64());
    for i in 0..3 {
        let now = Instant::now();
        let output = groth16_hint_runtime_tail_kernel::generate(&input);
        let t = now.elapsed().as_secs_f64();
        assert_eq!(output, expected);
        println!("run={i} seconds={t}");
    }
}
