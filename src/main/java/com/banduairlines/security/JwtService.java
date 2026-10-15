package com.banduairlines.security;

import com.banduairlines.model.Usuario;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    private static final String TIPO_ACCESS = "ACCESS";

    private final Key claveFirma;
    private final long expiracionMs;

    public JwtService(
            @Value("${app.jwt.secret}") String secreto,
            @Value("${app.jwt.expiration-ms}") long expiracionMs) {

        byte[] claveBytes = Decoders.BASE64.decode(secreto);

        this.claveFirma = Keys.hmacShaKeyFor(claveBytes);

        if (expiracionMs <= 0) {
            throw new IllegalArgumentException(
                    "La expiracion del JWT debe ser mayor que cero");
        }

        this.expiracionMs = expiracionMs;
    }

    // Representa la identidad obtenida de un JWT valido.
    public record DatosAcceso(Long idUsuario, Long idSesion) {}

    // Generar access token asociado a una sesion.
    public String generarToken(Usuario usuario, Long idSesion) {

        if (usuario == null || usuario.getId() == null || usuario.getEmail() == null
                || usuario.getRol() == null) {

            throw new IllegalArgumentException(
                    "El usuario debe tener ID, correo y rol");
        }

        if (idSesion == null || idSesion <= 0) {
            throw new IllegalArgumentException(
                    "El ID de sesion debe ser valido");
        }

        Date ahora = new Date();

        Date expiracion = new Date(
                ahora.getTime() + expiracionMs
        );

        return Jwts.builder()
                .setSubject(usuario.getId().toString())
                .claim("correo", usuario.getEmail())
                .claim("rol", usuario.getRol().name())
                .claim("tipo", TIPO_ACCESS)
                .claim("sid", idSesion.toString())
                .setIssuedAt(ahora)
                .setExpiration(expiracion)
                .signWith(
                        claveFirma,
                        SignatureAlgorithm.HS256
                )
                .compact();
    }

    // Validar firma, tipo y fechas del JWT.
    public Claims validarYObtenerClaims(String token) {

        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException(
                    "El JWT no puede estar vacio");
        }

        Jws<Claims> jwt = Jwts.parserBuilder()
                .setSigningKey(claveFirma)
                .build()
                .parseClaimsJws(token);

        if (!SignatureAlgorithm.HS256.getValue()
                .equals(jwt.getHeader().getAlgorithm())) {

            throw new JwtException(
                    "Algoritmo JWT no permitido");
        }

        Claims claims = jwt.getBody();

        if (!TIPO_ACCESS.equals(
                claims.get("tipo", String.class))) {

            throw new JwtException(
                    "El token no es un access token");
        }

        if (claims.getSubject() == null
                || claims.getSubject().isBlank()) {

            throw new JwtException(
                    "El JWT no contiene un ID de usuario");
        }

        if (claims.getExpiration() == null) {
            throw new JwtException(
                    "El JWT no contiene fecha de expiracion");
        }

        if (claims.getIssuedAt() == null) {
            throw new JwtException(
                    "El JWT no contiene fecha de emision");
        }

        if (claims.getIssuedAt().after(new Date())) {
            throw new JwtException(
                    "El JWT tiene una fecha de emision futura");
        }

        return claims;
    }

    // Obtener usuario y sesion, validando el JWT una sola vez.
    public DatosAcceso obtenerDatosAcceso(String token) {

        Claims claims = validarYObtenerClaims(token);

        String idSesion = claims.get("sid", String.class);

        if (idSesion == null || idSesion.isBlank()) {
            throw new JwtException(
                    "El JWT no contiene un ID de sesion");
        }
        try {
            Long idUsuario =
                    Long.valueOf(claims.getSubject());
            Long sesion =
                    Long.valueOf(idSesion);

            if (idUsuario <= 0 || sesion <= 0) {
                throw new JwtException(
                        "El JWT contiene identificadores invalidos");
            }

            return new DatosAcceso(
                    idUsuario,
                    sesion
            );

        } catch (NumberFormatException ex) {

            throw new JwtException(
                    "El JWT contiene identificadores invalidos",
                    ex
            );
        }
    }

    // Mantener este metodo para codigo que solo necesita el ID.
    public Long obtenerIdUsuario(String token) {

        Claims claims = validarYObtenerClaims(token);

        try {

            return Long.valueOf(claims.getSubject());

        } catch (NumberFormatException ex) {

            throw new JwtException(
                    "El JWT contiene un ID de usuario invalido", ex
            );
        }
    }

    public long obtenerSegundosExpiracion() {
        return expiracionMs / 1000;
    }
}