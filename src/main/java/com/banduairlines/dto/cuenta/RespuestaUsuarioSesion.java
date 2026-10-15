package com.banduairlines.dto.cuenta;

import com.banduairlines.model.enums.RolUsuario;

public record RespuestaUsuarioSesion(

        Long id,
        String nombres,
        String apellidos,
        String correo,
        RolUsuario rol

) {
}
