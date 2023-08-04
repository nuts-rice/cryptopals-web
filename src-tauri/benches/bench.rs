

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cryptopals_web::{eq_on_secret};
pub const TARGET_VAL: u64 = 587345609242879080;
pub fn true_eq_naughty(c: &mut Criterion) {
    c.bench_function("naughty true", |b| {
        b.iter(|| eq_on_secret(black_box(TARGET_VAL), true));
    });
}
pub fn false_eq_naughty(c: &mut Criterion) {
    c.bench_function("naughty false", |b| {
        b.iter(|| eq_on_secret(black_box(TARGET_VAL), false));
    });
}

criterion_group!(benches, true_eq_naughty, false_eq_naughty);
criterion_main!(benches);
