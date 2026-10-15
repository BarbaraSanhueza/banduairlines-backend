package com.banduairlines.service;

import com.banduairlines.dto.cuenta.SolicitudCambioContrasena;
import com.banduairlines.exception.ReglaNegocioException;
import com.banduairlines.exception.ValidacionException;
import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.repository.UsuarioRepository;
import com.banduairlines.security.UsuarioActual;
import com.banduairlines.service.impl.CambioContrasenaServiceImpl;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CambioContrasenaServiceImplTest {

    private UsuarioRepository usuarioRepository;
    private UsuarioActual usuarioActual;
    private BCryptPasswordEncoder passwordEncoder;
    private CambioContrasenaServiceImpl servicio;

    @BeforeEach
    void configurar() {
        usuarioRepository = mock(UsuarioRepository.class);
        usuarioActual = mock(UsuarioActual.class);
        passwordEncoder = new BCryptPasswordEncoder(4);
        servicio = new CambioContrasenaServiceImpl(
                usuarioRepository,
                usuarioActual,
                passwordEncoder
        );
        when(usuarioActual.exigirId()).thenReturn(1L);
    }

    @Test
    void cambioCorrecto_guardaNuevoResumenBCrypt() {
        Usuario usuario = usuario(RolUsuario.PASAJERO);
        when(usuarioRepository.findById(1L)).thenReturn(Optional.of(usuario));

        servicio.cambiar(new SolicitudCambioContrasena(
                "Clave-2025", "Clave-2026", "Clave-2026"
        ));

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(captor.capture());
        assertThat(captor.getValue().getContrasenaHash()).isNotEqualTo("Clave-2026");
        assertThat(passwordEncoder.matches("Clave-2026", captor.getValue().getContrasenaHash())).isTrue();
    }

    @Test
    void contrasenaActualIncorrecta_retornaCodigoEspecifico() {
        when(usuarioRepository.findById(1L)).thenReturn(Optional.of(usuario(RolUsuario.PASAJERO)));

        assertThatThrownBy(() -> servicio.cambiar(new SolicitudCambioContrasena(
                "Incorrecta-1", "Clave-2026", "Clave-2026"
        )))
                .isInstanceOf(ReglaNegocioException.class)
                .extracting("codigo")
                .isEqualTo("CONTRASENA_ACTUAL_INCORRECTA");
    }

    @Test
    void confirmacionDiferente_noCambiaResumen() {
        when(usuarioRepository.findById(1L)).thenReturn(Optional.of(usuario(RolUsuario.PASAJERO)));

        assertThatThrownBy(() -> servicio.cambiar(new SolicitudCambioContrasena(
                "Clave-2025", "Clave-2026", "Otra-2026"
        ))).isInstanceOf(ValidacionException.class);

        verify(usuarioRepository, never()).save(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void nuevaContrasenaInvalida_fallaBeanValidation() {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        SolicitudCambioContrasena solicitud = new SolicitudCambioContrasena(
                "Clave-2025", "Clave invalida", "Clave invalida"
        );

        assertThat(validator.validate(solicitud))
                .extracting(infraccion -> infraccion.getPropertyPath().toString())
                .contains("nuevaContrasena", "confirmacionContrasena");
    }

    @Test
    void superadmin_esRechazado() {
        when(usuarioRepository.findById(1L)).thenReturn(Optional.of(usuario(RolUsuario.SUPERADMIN)));

        assertThatThrownBy(() -> servicio.cambiar(new SolicitudCambioContrasena(
                "Clave-2025", "Clave-2026", "Clave-2026"
        ))).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void usuarioNoAutenticado_esRechazado() {
        when(usuarioActual.exigirId()).thenThrow(
                new AuthenticationCredentialsNotFoundException("Sin sesion")
        );

        assertThatThrownBy(() -> servicio.cambiar(new SolicitudCambioContrasena(
                "Clave-2025", "Clave-2026", "Clave-2026"
        ))).isInstanceOf(AuthenticationCredentialsNotFoundException.class);
    }

    private Usuario usuario(RolUsuario rol) {
        return Usuario.builder()
                .idUsuario(1L)
                .correo("actual@example.com")
                .nombres("Valentina")
                .apellidos("Rojas")
                .rol(rol)
                .activo(true)
                .contrasenaHash(passwordEncoder.encode("Clave-2025"))
                .build();
    }
}
