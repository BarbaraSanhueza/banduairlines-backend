package com.banduairlines.service.cuenta;

import com.banduairlines.model.CredencialRenovacion;
import com.banduairlines.model.Usuario;
import com.banduairlines.repository.CredencialRenovacionRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

@Service
public class SesionService {

    private static final int BYTES_TOKEN = 32;

    private static final String MOTIVO_RENOVACION = "RENOVACION";
    private static final String MOTIVO_CIERRE = "CIERRE_SESION";
    private static final String MOTIVO_CIERRE_TOTAL = "CIERRE_TOTAL";

    private final CredencialRenovacionRepository credencialRepository;
    private final long expiracionRefreshMs;

    private final SecureRandom secureRandom = new SecureRandom();

    public SesionService(
            CredencialRenovacionRepository credencialRepository,
            @Value("${app.jwt.refresh-expiration-ms}")
            long expiracionRefreshMs) {

        if (expiracionRefreshMs <= 0) {
            throw new IllegalArgumentException(
                    "La expiracion del refresh token debe ser positiva");
        }

        this.credencialRepository = credencialRepository;
        this.expiracionRefreshMs = expiracionRefreshMs;
    }

    // Resultado interno que usara AuthService.
    public record SesionEmitida(Long idSesion, String refreshToken,
            Instant expiracion, Usuario usuario) {}

    // 1. Crear una sesion despues de un login correcto.
    @Transactional
    public SesionEmitida crearSesion(Usuario usuario) {

        if (usuario == null
                || usuario.getId() == null
                || !Boolean.TRUE.equals(usuario.getActivo())) {

            throw new BadCredentialsException(
                    "No es posible crear la sesion");
        }

        return guardarNuevaCredencial(usuario);
    }

    // 2. Renovar una sesion, rotando el refresh token.
    @Transactional
    public SesionEmitida renovarSesion(String refreshToken) {

        validarFormatoToken(refreshToken);

        String hash = calcularHash(refreshToken);

        CredencialRenovacion credencial =
                credencialRepository.findByTokenHash(hash)
                        .orElseThrow(() ->
                                new BadCredentialsException(
                                        "Credencial de renovacion invalida")
                        );
        Instant ahora = Instant.now();

        if (credencial.getFechaRevocacion() != null) {
            throw new BadCredentialsException(
                    "Credencial de renovacion invalida");
        }

        if (credencial.getFechaExpiracion() == null
                || !credencial.getFechaExpiracion().isAfter(ahora)) {

            throw new CredencialVencidaException(
                    "Credencial de renovacion vencida");
        }

        Usuario usuario = credencial.getUsuario();

        if (usuario == null
                || !Boolean.TRUE.equals(usuario.getActivo())) {

            throw new BadCredentialsException(
                    "Credencial de renovacion invalida");
        }

        // El token anterior ya no podra volver a usarse.
        credencial.setFechaRevocacion(ahora);
        credencial.setMotivoRevocacion(MOTIVO_RENOVACION);

        credencialRepository.save(credencial);

        // Generar y almacenar una credencial completamente nueva.
        return guardarNuevaCredencial(usuario);
    }

    // 3. Revocar una sesion de un usuario autenticado.
    @Transactional
    public void revocarSesionPorToken(String refreshToken, Long idUsuario) {

        if (idUsuario == null) {
            throw new BadCredentialsException(
                    "Sesion invalida");
        }

        // Comprobar el formato de la credencial.
        validarFormatoToken(refreshToken);

        // Buscar la credencial por su hash.
        String hash = calcularHash(refreshToken);

        CredencialRenovacion credencial =
                credencialRepository.findByTokenHash(hash)
                        .orElseThrow(() ->
                                new BadCredentialsException(
                                        "Sesion invalida")
                        );

        // Comprobar que pertenece al usuario autenticado.
        Usuario usuario = credencial.getUsuario();

        if (usuario == null
                || !idUsuario.equals(usuario.getId())) {

            throw new BadCredentialsException(
                    "Sesion invalida");
        }

        // Comprobar que no haya sido revocada.
        if (credencial.getFechaRevocacion() != null) {
            throw new BadCredentialsException(
                    "Sesion invalida");
        }

        // Revocar la credencial.
        credencial.setFechaRevocacion(Instant.now());
        credencial.setMotivoRevocacion("CIERRE_SESION");

        credencialRepository.save(credencial);
    }

    // 4. Revocar todas las credenciales de un usuario.
    @Transactional
    public void revocarTodasLasSesiones(Long idUsuario) {

        if (idUsuario == null) {
            throw new IllegalArgumentException(
                    "El ID del usuario es obligatorio");
        }

        List<CredencialRenovacion> credenciales =
                credencialRepository
                        .findByUsuario_IdAndFechaRevocacionIsNull(
                                idUsuario
                        );
        Instant ahora = Instant.now();

        for (CredencialRenovacion credencial : credenciales) {

            credencial.setFechaRevocacion(ahora);
            credencial.setMotivoRevocacion(MOTIVO_CIERRE_TOTAL);
        }
        credencialRepository.saveAll(credenciales);
    }

    // Guarda una credencial nueva y devuelve el token original.
    private SesionEmitida guardarNuevaCredencial(Usuario usuario) {

        byte[] bytes = new byte[BYTES_TOKEN];

        secureRandom.nextBytes(bytes);

        String refreshToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);

        Instant ahora = Instant.now();

        Instant expiracion =
                ahora.plusMillis(expiracionRefreshMs);

        CredencialRenovacion credencial =
                new CredencialRenovacion();

        credencial.setUsuario(usuario);
        credencial.setTokenHash(calcularHash(refreshToken));
        credencial.setFechaCreacion(ahora);
        credencial.setFechaExpiracion(expiracion);

        CredencialRenovacion guardada =
                credencialRepository.saveAndFlush(credencial);

        return new SesionEmitida(
                guardada.getId(),
                refreshToken,
                expiracion,
                usuario
        );
    }

    // Verifica que el refresh token tenga el formato esperado.
    private void validarFormatoToken(String refreshToken) {

        if (refreshToken == null || !refreshToken.matches("[A-Za-z0-9_-]{43}")) {

            throw new BadCredentialsException(
                    "Credencial de renovacion invalida");
        }
    }

    // Calcula el hash SHA-256 del token.
    private String calcularHash(String token) {

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    token.getBytes(java.nio.charset.StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException ex) {

            throw new IllegalStateException(
                    "SHA-256 no esta disponible", ex);
        }
    }

    public static class CredencialVencidaException
            extends BadCredentialsException {

        public CredencialVencidaException(String mensaje) {
            super(mensaje);
        }
    }

}
