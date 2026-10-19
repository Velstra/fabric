use std::net::TcpListener;

/// Ask the OS for distinct unused ports instead of guessing from a PID.
/// Hold all reservations together so this set cannot contain duplicates.
/// Release them immediately before starting the child that binds them.
pub fn free_ports<const N: usize>() -> [u16; N] {
    let sockets: [TcpListener; N] =
        std::array::from_fn(|_| TcpListener::bind("127.0.0.1:0").expect("reserve test port"));
    std::array::from_fn(|index| sockets[index].local_addr().unwrap().port())
}
