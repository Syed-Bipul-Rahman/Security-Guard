//! Shannon entropy in bits per byte (0.0 for constant data, 8.0 for uniform random).

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            p * p.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaa"), 0.0);
        let all: Vec<u8> = (0..=255).collect();
        assert!((shannon_entropy(&all) - 8.0).abs() < 1e-12);
        assert!((shannon_entropy(&b"ab".repeat(50)) - 1.0).abs() < 1e-12);
    }
}
