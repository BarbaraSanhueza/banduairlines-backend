package com.banduairlines.service;

import com.banduairlines.dto.cuenta.RespuestaUsuario;
import com.banduairlines.dto.cuenta.SolicitudRegistro;
import com.banduairlines.exception.ConflictoException;
import com.banduairlines.exception.ValidacionException;
import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.Nivel;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.repository.UsuarioRepository;
import com.banduairlines.service.impl.RegistroPasajeroServiceImpl;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RegistroPasajeroServiceImplTest {

    private UsuarioRepository usuarioRepository;
    private RegistroPasajeroServiceImpl servicio;

    @BeforeEach
    void configurar() {
        usuarioRepository = mock(UsuarioRepository.class);
        servicio = new RegistroPasajeroServiceImpl(
                usuarioRepository,
                new BCryptPasswordEncoder(4)
        );
    }

    @Test
    void registroCorrecto_normalizaCorreoYAsignaRolNivelYHash() {
        when(usuarioRepository.saveAndFlush(any(Usuario.class)))
                .thenAnswer(invocacion -> {
                    Usuario usuario = invocacion.getArgument(0);
                    usuario.setIdUsuario(1L);
                    return usuario;
                });

        RespuestaUsuario respuesta = servicio.registrar(new SolicitudRegistro(
                " Valentina ",
                " Rojas ",
                " Valentina@Example.com ",
                "Clave-2026",
                "Clave-2026"
        ));

        ArgumentCaptor<Usuario> captor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).saveAndFlush(captor.capture());
        Usuario guardado = captor.getValue();

        assertThat(guardado.getCorreo()).isEqualTo("valentina@example.com");
        assertThat(guardado.getNombres()).isEqualTo("Valentina");
        assertThat(guardado.getApellidos()).isEqualTo("Rojas");
        assertThat(guardado.getRol()).isEqualTo(RolUsuario.PASAJERO);
        assertThat(guardado.getCuentaFidelizacion().getNivel()).isEqualTo(Nivel.BRONCE);
        assertThat(guardado.getCuentaFidelizacion().getSaldoMillas()).isZero();
        assertThat(guardado.getContrasenaHash()).isNotEqualTo("Clave-2026");
        assertThat(new BCryptPasswordEncoder().matches("Clave-2026", guardado.getContrasenaHash())).isTrue();
        assertThat(respuesta.nivel()).isEqualTo(Nivel.BRONCE);
        assertThat(respuesta.rol()).isEqualTo(RolUsuario.PASAJERO);
    }

    @Test
    void correoDuplicado_retornaCodigoEspecifico() {
        when(usuarioRepository.existsByCorreo("valentina@example.com")).thenReturn(true);

        assertThatThrownBy(() -> servicio.registrar(solicitudValida()))
                .isInstanceOf(ConflictoException.class)
                .extracting("codigo")
                .isEqualTo("CORREO_YA_REGISTRADO");

        verify(usuarioRepository, never()).saveAndFlush(any());
    }

    @Test
    void confirmacionDiferente_rechazaRegistro() {
        SolicitudRegistro solicitud = new SolicitudRegistro(
                "Valentina", "Rojas", "valentina@example.com",
                "Clave-2026", "Otra-2026"
        );

        assertThatThrownBy(() -> servicio.registrar(solicitud))
                .isInstanceOf(ValidacionException.class);
    }

    @Test
    void rolONivelEnviadoPorCliente_rechazaRegistro() {
        SolicitudRegistro solicitud = new SolicitudRegistro(
                "Valentina", "Rojas", "valentina@example.com",
                "Clave-2026", "Clave-2026", "ADMINISTRADOR", "ORO"
        );

        assertThatThrownBy(() -> servicio.registrar(solicitud))
                .isInstanceOf(ValidacionException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"corta", "Clave_2026", "Clave 2026"})
    void contrasenaInvalida_fallaBeanValidation(String contrasena) {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        SolicitudRegistro solicitud = new SolicitudRegistro(
                "Valentina", "Rojas", "valentina@example.com",
                contrasena, contrasena
        );

        assertThat(validator.validate(solicitud)).isNotEmpty();
    }

    @Test
    void correoInvalidoYContrasenaMuyLarga_fallanBeanValidation() {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        String larga = "A".repeat(33);
        SolicitudRegistro solicitud = new SolicitudRegistro(
                "Valentina", "Rojas", "correo-invalido", larga, larga
        );

        assertThat(validator.validate(solicitud))
                .extracting(v -> v.getPropertyPath().toString())
                .contains("correo", "contrasena", "confirmacionContrasena");
    }

    private SolicitudRegistro solicitudValida() {
        return new SolicitudRegistro(
                "Valentina", "Rojas", "valentina@example.com",
                "Clave-2026", "Clave-2026"
        );
    }
}
