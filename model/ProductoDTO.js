export function ProductoDTO(producto, fyh) {
    return {
        fyh,
        ...producto
    }
}