
package com.banduairlines.security;

import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.repository.UsuarioRepository;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.ResponseEntity;
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.util.Optional;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringJUnitConfig(classes = {
        SecurityConfig.class,
        RestAuthenticationEntryPoint.class,
        RestAccessDeniedHandler.class,
        SecurityAuthorizationTest.ConfiguracionPruebas.class
})
@WebAppConfiguration
@TestPropertySource(properties = "app.security.enabled=true")
class SecurityAuthorizationTest {

    private static final String TOKEN = "token-de-prueba";

    @Autowired
    private WebApplicationContext contexto;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UsuarioRepository usuarioRepository;

    private MockMvc mockMvc;

    @BeforeEach
    void configurar() {

        reset(jwtService, usuarioRepository);

        mockMvc = MockMvcBuilders
                .webAppContextSetup(contexto)
                .apply(SecurityMockMvcConfigurers.springSecurity())
                .build();
    }

    private void autenticarComo(RolUsuario rol) {

        Usuario usuario = new Usuario();

        usuario.setId(15L);
        usuario.setEmail("prueba@banduairlines.com");
        usuario.setRol(rol);
        usuario.setActivo(true);

        when(jwtService.obtenerIdUsuario(TOKEN))
                .thenReturn(15L);

        when(usuarioRepository.findById(15L))
                .thenReturn(Optional.of(usuario));
    }

    @Test
    void sinToken_retorna401() throws Exception {

        mockMvc.perform(get("/api/v1/cuentas/actual"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code")
                        .value("NO_AUTENTICADO"));
    }

    @Test
    void pasajero_puedeAccederPerfil() throws Exception {

        autenticarComo(RolUsuario.PASAJERO);

        mockMvc.perform(get("/api/v1/cuentas/actual")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk());
    }

    @Test
    void pasajero_noPuedeAdministrarCuentas() throws Exception {

        autenticarComo(RolUsuario.PASAJERO);

        mockMvc.perform(get("/api/v1/admin/cuentas/administradores")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code")
                        .value("ACCESO_DENEGADO"));
    }

    @Test
    void administrador_noPuedeAdministrarCuentas()
            throws Exception {

        autenticarComo(RolUsuario.ADMINISTRADOR);

        mockMvc.perform(get("/api/v1/admin/cuentas/administradores")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isForbidden());
    }

    @Test
    void superadmin_puedeAdministrarCuentas()
            throws Exception {

        autenticarComo(RolUsuario.SUPERADMIN);

        mockMvc.perform(get("/api/v1/admin/cuentas/administradores")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk());
    }

    @Test
    void superadmin_noPuedeAccederPerfil() throws Exception {

        autenticarComo(RolUsuario.SUPERADMIN);

        mockMvc.perform(get("/api/v1/cuentas/actual")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isForbidden());
    }

    @Test
    void administrador_puedeAccederRutaAdministrativa()
            throws Exception {

        autenticarComo(RolUsuario.ADMINISTRADOR);

        mockMvc.perform(get("/api/v1/admin/vuelos")
                        .header("Authorization", "Bearer " + TOKEN))
                .andExpect(status().isOk());
    }

    // Configuracion aislada: no utiliza PostgreSQL.
    @Configuration
    @EnableWebMvc
    static class ConfiguracionPruebas {

        @Bean
        JwtService jwtService() {
            return mock(JwtService.class);
        }

        @Bean
        UsuarioRepository usuarioRepository() {
            return mock(UsuarioRepository.class);
        }

        @Bean
        JwtAuthenticationFilter jwtAuthenticationFilter(
                JwtService jwtService,
                UsuarioRepository usuarioRepository) {

            return new JwtAuthenticationFilter(
                    jwtService,
                    usuarioRepository
            );
        }

        @Bean
        ControladorPruebas controladorPruebas() {
            return new ControladorPruebas();
        }
    }

    // Endpoints simulados exclusivos de esta prueba.
    @RestController
    static class ControladorPruebas {

        @GetMapping("/api/v1/cuentas/actual")
        ResponseEntity<String> perfil() {
            return ResponseEntity.ok("OK");
        }

        @GetMapping("/api/v1/admin/cuentas/administradores")
        ResponseEntity<String> administradores() {
            return ResponseEntity.ok("OK");
        }

        @GetMapping("/api/v1/admin/vuelos")
        ResponseEntity<String> vuelos() {
            return ResponseEntity.ok("OK");
        }
    }
}
