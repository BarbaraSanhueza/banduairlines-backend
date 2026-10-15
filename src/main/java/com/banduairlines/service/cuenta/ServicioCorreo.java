package com.banduairlines.service.cuenta;

import java.time.Instant;

/**
 * Contrato de integracion con el servicio de correo compartido del modulo de
 * autenticacion. Este modulo no proporciona una implementacion alternativa.
 */
public interface ServicioCorreo {

    void enviarCodigoCambioCorreo(
            String destinatario,
            String codigo,
            Instant fechaExpiracion
    );
}
