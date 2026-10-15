package com.banduairlines.service.cuenta;

import com.banduairlines.dto.cuenta.RespuestaSesion;
import com.banduairlines.dto.cuenta.RespuestaUsuarioSesion;
import com.banduairlines.dto.cuenta.SolicitudCierreSesion;
import com.banduairlines.dto.cuenta.SolicitudInicioSesion;
import com.banduairlines.dto.cuenta.SolicitudRenovacion;
import com.banduairlines.exception.ErrorAutenticacionException;
import com.banduairlines.model.Usuario;
import com.banduairlines.repository.UsuarioRepository;
import com.banduairlines.security.JwtService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;

@Service
public class AuthService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final SesionService sesionService;

    public AuthService(
            UsuarioRepository usuarioRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            SesionService sesionService) {

        this.usuarioRepository = usuarioRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.sesionService = sesionService;
    }

    // 1. Iniciar sesion con correo y contraseña.
    @Transactional
    public RespuestaSesion iniciarSesion(
            SolicitudInicioSesion solicitud) {

        String correo = solicitud.correo()
                .trim()
                .toLowerCase(Locale.ROOT);

        Usuario usuario = usuarioRepository.findByEmail(correo)
                .orElseThrow(this::credencialesInvalidas);

        // No permitir el ingreso de cuentas inactivas.
        if (!Boolean.TRUE.equals(usuario.getActivo())) {
            throw credencialesInvalidas();
        }

        // La cuenta debe tener contraseña y rol.
        if (usuario.getPasswordHash() == null
                || usuario.getRol() == null) {

            throw credencialesInvalidas();
        }

        // Comparar la contraseña con el hash BCrypt.
        boolean contrasenaCorrecta = passwordEncoder.matches(
                solicitud.contrasena(),
                usuario.getPasswordHash()
        );

        if (!contrasenaCorrecta) {
            throw credencialesInvalidas();
        }

        // Crear la sesion y su refresh token.
        SesionService.SesionEmitida sesion =
                sesionService.crearSesion(usuario);

        // Generar la respuesta con los dos tokens.
        return construirRespuesta(sesion);
    }

    // 2. Renovar una sesion existente.
    @Transactional
    public RespuestaSesion renovarSesion(
            SolicitudRenovacion solicitud) {

        SesionService.SesionEmitida sesion;

        try {
            sesion = sesionService.renovarSesion(
                    solicitud.credencialRenovacion()
            );

        } catch (SesionService.CredencialVencidaException ex) {

            throw new ErrorAutenticacionException(
                    "CREDENCIAL_RENOVACION_VENCIDA",
                    "La credencial de renovacion ha expirado"
            );

        } catch (BadCredentialsException ex) {

            throw new ErrorAutenticacionException(
                    "CREDENCIAL_RENOVACION_INVALIDA",
                    "La credencial de renovacion no es valida"
            );
        }

        // La renovacion genera una nueva pareja de credenciales.
        return construirRespuesta(sesion);
    }

    // 3. Cerrar la sesion de un usuario autenticado.
    @Transactional
    public void cerrarSesion(
            SolicitudCierreSesion solicitud,
            Long idUsuario) {

        try {
            sesionService.revocarSesionPorToken(
                    solicitud.credencialRenovacion(),
                    idUsuario
            );

        } catch (BadCredentialsException ex) {

            throw new ErrorAutenticacionException(
                    "NO_AUTENTICADO",
                    "No fue posible validar la sesion"
            );
        }
    }

    // 4. Construir la respuesta publica de autenticacion.
    private RespuestaSesion construirRespuesta(
            SesionService.SesionEmitida sesion) {

        Usuario usuario = sesion.usuario();

        String accessToken =
                jwtService.generarToken(usuario);

        RespuestaUsuarioSesion usuarioRespuesta =
                new RespuestaUsuarioSesion(
                        usuario.getId(),
                        usuario.getNombre(),
                        usuario.getApellido(),
                        usuario.getEmail(),
                        usuario.getRol()
                );

        return new RespuestaSesion(
                accessToken,
                sesion.refreshToken(),
                "Bearer",
                jwtService.obtenerSegundosExpiracion(),
                usuarioRespuesta
        );
    }

    // Mismo error para correo inexistente y contraseña incorrecta.
    private ErrorAutenticacionException credencialesInvalidas() {

        return new ErrorAutenticacionException(
                "CREDENCIALES_INVALIDAS",
                "Correo o contraseña incorrectos"
        );
    }
}
