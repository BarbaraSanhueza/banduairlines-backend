package com.banduairlines.dto.cuenta;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record SolicitudCierreSesion(

        @NotBlank(message = "La credencial de renovacion es obligatoria")
        @Size(max = 256, message = "La credencial de renovacion es demasiado larga")
        String credencialRenovacion
) {
}
