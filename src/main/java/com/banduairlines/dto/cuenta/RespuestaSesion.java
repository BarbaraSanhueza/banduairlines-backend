package com.banduairlines.dto.cuenta;

public record RespuestaSesion(

        String credencialAcceso,
        String credencialRenovacion,
        String tipoCredencial,
        long segundosExpiracion,
        RespuestaUsuarioSesion usuario

) {
}
