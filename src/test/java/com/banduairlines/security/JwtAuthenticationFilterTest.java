
package com.banduairlines.security;

import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.repository.UsuarioRepository;
import com.banduairlines.repository.CredencialRenovacionRepository;

import io.jsonwebtoken.JwtException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {

    private JwtService jwtService;
    private UsuarioRepository usuarioRepository;
    private CredencialRenovacionRepository credencialRepository;
    private JwtAuthenticationFilter filtro;

    @BeforeEach
    void setUp() {

        jwtService = mock(JwtService.class);

        usuarioRepository = mock(UsuarioRepository.class);
        credencialRepository = mock(CredencialRenovacionRepository.class);

        filtro = new JwtAuthenticationFilter(
                jwtService,
                usuarioRepository,
                credencialRepository
        );

        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private Usuario crearUsuario(
            RolUsuario rol,
            boolean activo) {

        Usuario usuario = new Usuario();

        usuario.setIdUsuario(15L);
        usuario.setCorreo("usuario@banduairlines.com");
        usuario.setRol(rol);
        usuario.setActivo(activo);

        return usuario;
    }

    private MockHttpServletRequest crearPeticion(
            String token) {

        MockHttpServletRequest request =
                new MockHttpServletRequest(
                        "GET",
                        "/api/v1/cuentas/actual"
                );

        if (token != null) {
            request.addHeader(
                    "Authorization",
                    "Bearer " + token
            );
        }

        return request;
    }

    private void ejecutarFiltro(
            MockHttpServletRequest request)
            throws Exception {

        filtro.doFilter(
                request,
                new MockHttpServletResponse(),
                new MockFilterChain()
        );
    }

    @Test
    void sinToken_noAutenticaUsuario()
            throws Exception {

        ejecutarFiltro(crearPeticion(null));

        Authentication autenticacion =
                SecurityContextHolder.getContext()
                        .getAuthentication();

        assertThat(autenticacion).isNull();

        verifyNoInteractions(
                jwtService,
                usuarioRepository,
                credencialRepository
        );
    }

    @Test
    void tokenValido_yUsuarioActivo_autentica()
            throws Exception {

        Usuario usuario = crearUsuario(
                RolUsuario.PASAJERO,
                true
        );

        when(
                jwtService.obtenerDatosAcceso("token-valido")
        ).thenReturn(new JwtService.DatosAcceso(15L, 99L));

        when(credencialRepository
                .existsByIdAndUsuario_IdUsuarioAndFechaRevocacionIsNullAndFechaExpiracionAfter(
                        eq(99L), eq(15L), any()
                )).thenReturn(true);

        when(
                usuarioRepository.findById(15L)
        ).thenReturn(Optional.of(usuario));

        ejecutarFiltro(
                crearPeticion("token-valido")
        );

        Authentication autenticacion =
                SecurityContextHolder.getContext()
                        .getAuthentication();

        assertThat(autenticacion).isNotNull();
        assertThat(autenticacion.isAuthenticated()).isTrue();

        assertThat(
                autenticacion.getPrincipal()
        ).isEqualTo(
                new UsuarioAutenticado(
                        15L,
                        "usuario@banduairlines.com",
                        RolUsuario.PASAJERO
                )
        );

        assertThat(
                autenticacion.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        ).containsExactly("ROLE_PASAJERO");
    }

    @Test
    void tokenInvalido_noAutenticaUsuario()
            throws Exception {

        when(
                jwtService.obtenerDatosAcceso("token-invalido")
        ).thenThrow(
                new JwtException("Firma JWT invalida")
        );

        ejecutarFiltro(
                crearPeticion("token-invalido")
        );

        assertThat(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        ).isNull();
    }

    @Test
    void usuarioDesactivado_noAutentica()
            throws Exception {

        Usuario usuario = crearUsuario(
                RolUsuario.PASAJERO,
                false
        );

        when(
                jwtService.obtenerDatosAcceso("token-valido")
        ).thenReturn(new JwtService.DatosAcceso(15L, 99L));

        when(credencialRepository
                .existsByIdAndUsuario_IdUsuarioAndFechaRevocacionIsNullAndFechaExpiracionAfter(
                        eq(99L), eq(15L), any()
                )).thenReturn(true);

        when(
                usuarioRepository.findById(15L)
        ).thenReturn(Optional.of(usuario));

        ejecutarFiltro(
                crearPeticion("token-valido")
        );

        assertThat(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        ).isNull();
    }

    @Test
    void usuarioInexistente_noAutentica()
            throws Exception {

        when(
                jwtService.obtenerDatosAcceso("token-valido")
        ).thenReturn(new JwtService.DatosAcceso(15L, 99L));

        when(credencialRepository
                .existsByIdAndUsuario_IdUsuarioAndFechaRevocacionIsNullAndFechaExpiracionAfter(
                        eq(99L), eq(15L), any()
                )).thenReturn(true);

        when(
                usuarioRepository.findById(15L)
        ).thenReturn(Optional.empty());

        ejecutarFiltro(
                crearPeticion("token-valido")
        );

        assertThat(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        ).isNull();
    }

    @Test
    void usuarioConRolActualizado_utilizaRolDeBaseDeDatos()
            throws Exception {

        Usuario usuario = crearUsuario(
                RolUsuario.SUPERADMIN,
                true
        );

        when(
                jwtService.obtenerDatosAcceso("token-valido")
        ).thenReturn(new JwtService.DatosAcceso(15L, 99L));

        when(credencialRepository
                .existsByIdAndUsuario_IdUsuarioAndFechaRevocacionIsNullAndFechaExpiracionAfter(
                        eq(99L), eq(15L), any()
                )).thenReturn(true);

        when(
                usuarioRepository.findById(15L)
        ).thenReturn(Optional.of(usuario));

        ejecutarFiltro(
                crearPeticion("token-valido")
        );

        Authentication autenticacion =
                SecurityContextHolder.getContext()
                        .getAuthentication();

        assertThat(autenticacion).isNotNull();

        assertThat(
                autenticacion.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList()
        ).containsExactly("ROLE_SUPERADMIN");
    }
}
