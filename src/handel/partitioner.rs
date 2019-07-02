use std::ops::RangeInclusive;

use failure::Fail;

use crate::handel::utils::log2;
use crate::handel::MultiSignature;



#[derive(Clone, Debug, Fail, PartialEq)]
pub enum PartitioningError {
    #[fail(display = "Invalid level: {}", _0)]
    InvalidLevel(usize),
}


#[derive(Clone, Debug)]
pub struct BinomialPartitioner {
    // The ID of the node itself
    pub node_id: usize,

    // The maximum ID, ideally this should be 2^k-1
    pub max_id: usize,

    // the number of levels
    pub num_levels: usize
}

impl BinomialPartitioner {
    pub fn new(node_id: usize, max_id: usize) -> Self {
        BinomialPartitioner {
            node_id,
            max_id,
            num_levels: log2(max_id) + 2
        }
    }

    pub fn size(&self, level: usize) -> usize {
        2_usize.pow(level as u32)
    }

    pub fn range(&self, level: usize) -> Result<RangeInclusive<usize>, PartitioningError> {
        if level == 0 {
            Ok(self.node_id ..= self.node_id)
        }
        else if level >= self.num_levels {
            Err(PartitioningError::InvalidLevel(level))
        }
        else {
            // mask for bits which cover the range
            let m = (1 << (level - 1)) - 1;
            // bit that must be flipped
            let f = 1 << (level - 1);

            let min = (self.node_id ^ f) & !m;
            let max = (self.node_id ^ f) | m;

            //debug!("node_id={:b}, level={}, m={:b}, f={:b}, min={:b}, max={:b}", self.node_id, level, m, f, min, max);

            Ok(min ..= max)
        }
    }

    pub fn combine(&self, signatures: Vec<&MultiSignature>, level: usize) -> Option<MultiSignature> {
        let mut combined = (*signatures.first()?).clone();

        for signature in signatures.iter().skip(1) {
            combined.add_multisig(signature);
        }

        Some(combined)
    }
}


#[cfg(test)]
mod tests {
    use super::{BinomialPartitioner, PartitioningError};

    #[test]
    fn test_partitioner() {
        /*
            ---ID---   -Level-
            0    000   . . 2 .
            1    001   . . 2 .
            2    010   . 1 . .
            3    011   0 . . .
            4    100   . . . 3
            5    101   . . . 3
            6    110   . . . 3
            7    111   . . . 3

        node_id = 3
        level = 3
        m = (1 << level - 1) - 1 = 100 - 1 = 011
        f = (1 << level)                   = 100
        */

        let partitioner = BinomialPartitioner::new(3, 7);

        assert_eq!(partitioner.num_levels, 4);
        assert_eq!(partitioner.range(0), Ok(3..=3), "Level 0");
        assert_eq!(partitioner.range(1), Ok(2..=2), "Level 1");
        assert_eq!(partitioner.range(2), Ok(0..=1), "Level 2");
        assert_eq!(partitioner.range(3), Ok(4..=7), "Level 3");
        assert_eq!(partitioner.range(4), Err(PartitioningError::InvalidLevel(4)));
    }
}
