use std::fmt::Debug;
use serde_json::Value;


pub trait JoseHeader: Debug + Send + Sync {
    // Return claim count
    fn len(&self) -> usize;

    fn claim(&self, key: &str) -> Option<&Value>;
    
    fn box_clone(&self) -> Box<dyn JoseHeader>;
}

impl Clone for Box<dyn JoseHeader> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}
