
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

    // Constructor: obtiene las propiedades del JWT.
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

    // Genera un access token para un usuario registrado.
    public String generarToken(Usuario usuario) {

        if (usuario == null
                || usuario.getId() == null
                || usuario.getEmail() == null
                || usuario.getRol() == null) {

            throw new IllegalArgumentException(
                    "El usuario debe tener ID, correo y rol");
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
                .setIssuedAt(ahora)
                .setExpiration(expiracion)
                .signWith(
                        claveFirma,
                        SignatureAlgorithm.HS256
                )
                .compact();
    }

    // Valida la firma, el tipo de token y su expiracion.
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

    // Obtiene el ID del usuario indicado en el JWT.
    public Long obtenerIdUsuario(String token) {

        Claims claims = validarYObtenerClaims(token);

        try {
            return Long.valueOf(claims.getSubject());

        } catch (NumberFormatException ex) {

            throw new JwtException(
                    "El JWT contiene un ID de usuario invalido",
                    ex
            );
        }
    }

    // Devuelve la duracion del access token en segundos.
    public long obtenerSegundosExpiracion() {
        return expiracionMs / 1000;
    }
}
