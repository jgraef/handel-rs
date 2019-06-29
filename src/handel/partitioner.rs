use std::sync::Arc;

use failure::Fail;

use crate::handel::IdentityRegistry;
use crate::handel::Identity;
use crate::handel::utils::log_2;


#[derive(Clone, Debug, Fail)]
pub enum PartitioningError {
    #[fail(display = "Invalid level: {}", _0)]
    InvalidLevel(usize),
    #[fail(display = "Empty level: {}", _0)]
    EmptyLevel(usize),
}



pub struct BinomialPartitioner {
    // The ID of the node itself
    pub node_id: usize,

    pub max_level: usize,

    pub size: usize,

    // All other identities
    pub identities: Arc<IdentityRegistry>,
}

impl BinomialPartitioner {
    pub fn new(node_id: usize, identities: Arc<IdentityRegistry>) -> Self {
        BinomialPartitioner {
            node_id,
            max_level: log_2(identities.len()),
            size: identities.len(),
            identities,
        }
    }

    pub fn identities_at(&self, level: usize) -> Result<Vec<Arc<Identity>>, PartitioningError> {
        let (min, max) = self.range_level(level)?;
        Ok(self.identities.get_by_id_range(min, max))
    }

    fn range_level(&self, level: usize) -> Result<(usize, usize), PartitioningError> {
        if level == 0 {
            return Ok((self.node_id, self.node_id));
        }

        debug!("partitioning: node_id={}, max_level={}, size={}", self.node_id, self.max_level, self.size);

        if level > self.max_level + 1 {
            return Err(PartitioningError::InvalidLevel(level));
        }

        let mut min = 0;
        let mut max = self.max_level.pow(2);
        let inverse_idx = level - 1;

        let mut i = self.max_level - 1;
        while i <= inverse_idx && i >= 0 && min < max {
            let middle = (max + min) / 2;
            debug!("min={}, max={}, inverse_idx={}, middle={}", min, max, inverse_idx, middle);

            if (self.node_id >> i) & 1 == 1 {
                if i == inverse_idx {
                    max = middle;
                }
                else {
                    min = middle;
                }
            }
            else {
                if i == inverse_idx {
                    min = middle;
                }
                else {
                    max = middle;
                }
            }

            i -= 1;
        }

        if min >= self.size {
            return Err(PartitioningError::EmptyLevel(level));
        }

        if max > self.size {
            max = self.size;
        }

        Ok((min, max))
    }

    fn range_level_inverse(&self, level: usize) -> Result<(usize, usize), PartitioningError> {
        if level > self.max_level + 1 {
            return Err(PartitioningError::InvalidLevel(level));
        }

        let mut min = 0;
        let mut max = self.max_level.pow(2);
        let max_idx = level - 1;

        let mut i = self.max_level - 1;
        while i >= max_idx && i >= 0 && min < max {
            let middle = (max + min) / 2;

            if (self.node_id >> i) & 1 == 1 {
                min = middle;
            }
            else {
                max = middle;
            }

            i -= 1;
        }

        if max > self.size {
            max = self.size;
        }

        Ok((min, max))
    }

    fn size(&self, level: usize) -> Result<usize, PartitioningError> {
        let (min, max) = self.range_level(level)?;
        Ok(max - min)
    }

    pub fn levels(&self) -> Vec<usize> {
        let mut levels = Vec::new();
        for i in 0..self.max_level {
            if self.range_level(i).is_ok() {
                levels.push(i)
            }
        }
        levels
    }
}
