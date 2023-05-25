pub mod base64;
mod blake;
pub mod checksum;
pub mod emoji;
mod encoders;
pub mod encryption;
pub mod shapes;

#[macro_use]
extern crate lazy_static;

// pub fn add(left: usize, right: usize) -> usize {
//     left + right
// }

// #[cfg(test)]
// mod tests {

//     use super::*;

//     #[test]
//     fn it_works() {
//         let result = add(2, 2);
//         assert_eq!(result, 4);
//     }
// }
