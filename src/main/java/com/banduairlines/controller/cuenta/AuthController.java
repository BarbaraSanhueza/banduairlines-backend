package com.banduairlines.controller.cuenta;

import com.banduairlines.dto.cuenta.RespuestaSesion;
import com.banduairlines.dto.cuenta.SolicitudCierreSesion;
import com.banduairlines.dto.cuenta.SolicitudInicioSesion;
import com.banduairlines.dto.cuenta.SolicitudRenovacion;
import com.banduairlines.exception.ApiError;
import com.banduairlines.exception.ErrorAutenticacionException;
import com.banduairlines.security.UsuarioActual;
import com.banduairlines.service.cuenta.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;
    private final UsuarioActual usuarioActual;

    public AuthController(
            AuthService authService,
            UsuarioActual usuarioActual) {

        this.authService = authService;
        this.usuarioActual = usuarioActual;
    }

    // POST /api/v1/auth/inicio-sesion
    @PostMapping("/inicio-sesion")
    public ResponseEntity<RespuestaSesion> iniciarSesion(
            @Valid @RequestBody SolicitudInicioSesion solicitud) {

        RespuestaSesion respuesta =
                authService.iniciarSesion(solicitud);

        return ResponseEntity.ok(respuesta);
    }

    // POST /api/v1/auth/renovacion
    @PostMapping("/renovacion")
    public ResponseEntity<RespuestaSesion> renovarSesion(
            @Valid @RequestBody SolicitudRenovacion solicitud) {

        RespuestaSesion respuesta =
                authService.renovarSesion(solicitud);

        return ResponseEntity.ok(respuesta);
    }

    // POST /api/v1/auth/cierre-sesion
    @PostMapping("/cierre-sesion")
    public ResponseEntity<Void> cerrarSesion(
            @Valid @RequestBody SolicitudCierreSesion solicitud) {

        Long idUsuario = usuarioActual.exigirId();

        authService.cerrarSesion(
                solicitud,
                idUsuario
        );

        return ResponseEntity.noContent().build();
    }

    // Manejo de errores propios de autenticacion.
    @ExceptionHandler(ErrorAutenticacionException.class)
    public ResponseEntity<ApiError> manejarErrorAutenticacion(
            ErrorAutenticacionException ex,
            HttpServletRequest request) {

        ApiError error = new ApiError(
                Instant.now(),
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                ex.getCodigo(),
                ex.getMessage(),
                request.getRequestURI(),
                List.of()
        );

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(error);
    }
}
