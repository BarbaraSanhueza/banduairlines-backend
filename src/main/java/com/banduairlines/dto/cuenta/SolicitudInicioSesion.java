package com.banduairlines.dto.cuenta;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SolicitudInicioSesion(

        @NotBlank(message = "El correo es obligatorio")
        @Email(message = "El correo debe tener un formato valido")
        @Size(max = 150, message = "El correo no puede superar 150 caracteres")
        String correo,

        @NotBlank(message = "La contraseña es obligatoria")
        String contrasena
) {
}
