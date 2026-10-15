package com.banduairlines.exception;

public class ErrorAutenticacionException
        extends RuntimeException {

    private final String codigo;

    public ErrorAutenticacionException(
            String codigo,
            String mensaje) {

        super(mensaje);
        this.codigo = codigo;
    }

    public String getCodigo() {
        return codigo;
    }
}
