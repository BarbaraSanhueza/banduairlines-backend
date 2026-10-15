
package com.banduairlines.security;

import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.RolUsuario;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {

    private JwtService jwtService;
    private String secreto;

    @BeforeEach
    void setUp() {

        // Clave aleatoria exclusiva para cada prueba.
        secreto = Encoders.BASE64.encode(
                Keys.secretKeyFor(
                        SignatureAlgorithm.HS256
                ).getEncoded()
        );

        // Access token con 15 minutos de duracion.
        jwtService = new JwtService(secreto, 900000);
    }

    private Usuario crearUsuario() {

        Usuario usuario = new Usuario();

        usuario.setId(15L);
        usuario.setEmail("pasajero@banduairlines.com");
        usuario.setRol(RolUsuario.PASAJERO);
        usuario.setActivo(true);

        return usuario;
    }

    @Test
    void generarToken_debeContenerDatosCorrectos() {

        Usuario usuario = crearUsuario();

        String token = jwtService.generarToken(usuario);

        Claims claims =
                jwtService.validarYObtenerClaims(token);

        assertThat(token).isNotBlank();
        assertThat(claims.getSubject()).isEqualTo("15");

        assertThat(
                claims.get("correo", String.class)
        ).isEqualTo("pasajero@banduairlines.com");

        assertThat(
                claims.get("rol", String.class)
        ).isEqualTo("PASAJERO");

        assertThat(
                claims.get("tipo", String.class)
        ).isEqualTo("ACCESS");

        assertThat(claims.getIssuedAt()).isNotNull();
        assertThat(claims.getExpiration()).isNotNull();
    }

    @Test
    void obtenerIdUsuario_conTokenValido_retornaId() {

        String token =
                jwtService.generarToken(crearUsuario());

        Long id = jwtService.obtenerIdUsuario(token);

        assertThat(id).isEqualTo(15L);
    }

    @Test
    void validarToken_conFirmaIncorrecta_lanzaExcepcion() {

        // Generamos un JWT con otra clave secreta.
        String otroSecreto = Encoders.BASE64.encode(
                Keys.secretKeyFor(
                        SignatureAlgorithm.HS256
                ).getEncoded()
        );

        JwtService otroJwtService =
                new JwtService(otroSecreto, 900000);

        String token =
                otroJwtService.generarToken(crearUsuario());

        // Nuestro servicio no debe aceptar esa firma.
        assertThatThrownBy(() ->
                jwtService.validarYObtenerClaims(token)
        ).isInstanceOf(JwtException.class);
    }

    @Test
    void validarTokenExpirado_lanzaExcepcion() {

        long ahora = System.currentTimeMillis();

        String tokenExpirado = Jwts.builder()
                .setSubject("15")
                .claim("correo", "pasajero@banduairlines.com")
                .claim("rol", "PASAJERO")
                .claim("tipo", "ACCESS")
                .setIssuedAt(new Date(ahora - 180000))
                .setExpiration(new Date(ahora - 60000))
                .signWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(secreto)
                        ),
                        SignatureAlgorithm.HS256
                )
                .compact();

        assertThatThrownBy(() ->
                jwtService.validarYObtenerClaims(tokenExpirado)
        ).isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void validarTokenSinTipoAccess_lanzaExcepcion() {

        long ahora = System.currentTimeMillis();

        String tokenSinTipo = Jwts.builder()
                .setSubject("15")
                .setIssuedAt(new Date(ahora))
                .setExpiration(new Date(ahora + 900000))
                .signWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(secreto)
                        ),
                        SignatureAlgorithm.HS256
                )
                .compact();

        assertThatThrownBy(() ->
                jwtService.validarYObtenerClaims(tokenSinTipo)
        ).isInstanceOf(JwtException.class);
    }

    @Test
    void obtenerIdUsuario_conIdInvalido_lanzaExcepcion() {

        long ahora = System.currentTimeMillis();

        String token = Jwts.builder()
                .setSubject("identificador-invalido")
                .claim("tipo", "ACCESS")
                .setIssuedAt(new Date(ahora))
                .setExpiration(new Date(ahora + 900000))
                .signWith(
                        Keys.hmacShaKeyFor(
                                Decoders.BASE64.decode(secreto)
                        ),
                        SignatureAlgorithm.HS256
                )
                .compact();

        assertThatThrownBy(() ->
                jwtService.obtenerIdUsuario(token)
        ).isInstanceOf(JwtException.class);
    }

    @Test
    void obtenerSegundosExpiracion_retorna900() {

        assertThat(
                jwtService.obtenerSegundosExpiracion()
        ).isEqualTo(900);
    }
}
