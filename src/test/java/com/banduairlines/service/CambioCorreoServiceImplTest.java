package com.banduairlines.service;

import com.banduairlines.dto.cuenta.ConfirmacionCambioCorreo;
import com.banduairlines.dto.cuenta.RespuestaSolicitudCambioCorreo;
import com.banduairlines.dto.cuenta.RespuestaUsuario;
import com.banduairlines.exception.ConflictoException;
import com.banduairlines.exception.RecursoNoEncontradoException;
import com.banduairlines.exception.RecursoVencidoException;
import com.banduairlines.exception.ReglaNegocioException;
import com.banduairlines.exception.ValidacionException;
import com.banduairlines.model.CuentaFidelizacion;
import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.Nivel;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.repository.SolicitudCambioCorreoRepository;
import com.banduairlines.repository.UsuarioRepository;
import com.banduairlines.security.UsuarioActual;
import com.banduairlines.service.cuenta.ServicioCorreo;
import com.banduairlines.service.impl.CambioCorreoServiceImpl;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CambioCorreoServiceImplTest {

    private static final Instant AHORA = Instant.parse("2026-10-15T20:00:00Z");

    private UsuarioRepository usuarioRepository;
    private SolicitudCambioCorreoRepository solicitudRepository;
    private UsuarioActual usuarioActual;
    private ServicioCorreo servicioCorreo;
    private BCryptPasswordEncoder passwordEncoder;
    private CambioCorreoServiceImpl servicio;

    @BeforeEach
    void configurar() {
        usuarioRepository = mock(UsuarioRepository.class);
        solicitudRepository = mock(SolicitudCambioCorreoRepository.class);
        usuarioActual = mock(UsuarioActual.class);
        servicioCorreo = mock(ServicioCorreo.class);
        passwordEncoder = new BCryptPasswordEncoder(4);
        servicio = new CambioCorreoServiceImpl(
                usuarioRepository,
                solicitudRepository,
                usuarioActual,
                passwordEncoder,
                Optional.of(servicioCorreo),
                Clock.fixed(AHORA, ZoneOffset.UTC),
                30
        );
        when(usuarioActual.exigirId()).thenReturn(1L);
    }

    @Test
    void solicitudCorrecta_generaHashEnviaCodigoYNoLoExpone() {
        Usuario usuario = usuario(RolUsuario.PASAJERO);
        prepararUsuarioActual(usuario);
        when(solicitudRepository.saveAndFlush(any()))
                .thenAnswer(invocacion -> {
                    com.banduairlines.model.SolicitudCambioCorreo solicitud = invocacion.getArgument(0);
                    solicitud.setIdSolicitud(12L);
                    return solicitud;
                });

        RespuestaSolicitudCambioCorreo respuesta = servicio.solicitar(
                new com.banduairlines.dto.cuenta.SolicitudCambioCorreo(
                        " Correo.Nuevo@Example.com "
                )
        );

        ArgumentCaptor<com.banduairlines.model.SolicitudCambioCorreo> entidadCaptor =
                ArgumentCaptor.forClass(com.banduairlines.model.SolicitudCambioCorreo.class);
        verify(solicitudRepository).saveAndFlush(entidadCaptor.capture());

        ArgumentCaptor<String> codigoCaptor = ArgumentCaptor.forClass(String.class);
        verify(servicioCorreo).enviarCodigoCambioCorreo(
                org.mockito.ArgumentMatchers.eq("correo.nuevo@example.com"),
                codigoCaptor.capture(),
                org.mockito.ArgumentMatchers.eq(Instant.parse("2026-10-15T20:30:00Z"))
        );

        assertThat(codigoCaptor.getValue()).matches("\\d{6}");
        assertThat(entidadCaptor.getValue().getCodigoHash()).isNotEqualTo(codigoCaptor.getValue());
        assertThat(passwordEncoder.matches(
                codigoCaptor.getValue(),
                entidadCaptor.getValue().getCodigoHash()
        )).isTrue();
        assertThat(respuesta.idSolicitud()).isEqualTo(12L);
        assertThat(respuesta.correoEnmascarado()).isEqualTo("c*****@example.com");
        assertThat(RespuestaSolicitudCambioCorreo.class.getRecordComponents())
                .extracting(component -> component.getName())
                .doesNotContain("codigo");
        assertThat(usuario.getCorreo()).isEqualTo("actual@example.com");
    }

    @Test
    void nuevaSolicitud_invalidaAnterior() {
        prepararUsuarioActual(usuario(RolUsuario.PASAJERO));
        com.banduairlines.model.SolicitudCambioCorreo anterior = solicitudVigente("111111");
        when(solicitudRepository
                .findByUsuario_IdUsuarioAndFechaConfirmacionIsNullAndFechaCancelacionIsNull(1L))
                .thenReturn(List.of(anterior));
        when(solicitudRepository.saveAndFlush(any()))
                .thenAnswer(invocacion -> {
                    com.banduairlines.model.SolicitudCambioCorreo nueva = invocacion.getArgument(0);
                    nueva.setIdSolicitud(13L);
                    return nueva;
                });

        servicio.solicitar(new com.banduairlines.dto.cuenta.SolicitudCambioCorreo(
                "nuevo@example.com"
        ));

        assertThat(anterior.getFechaCancelacion()).isEqualTo(AHORA);
        assertThat(anterior.getCodigoHash()).isNull();
        verify(solicitudRepository).saveAll(List.of(anterior));
    }

    @Test
    void correoIgualAlActual_esInvalido() {
        prepararUsuarioActual(usuario(RolUsuario.PASAJERO));

        assertThatThrownBy(() -> servicio.solicitar(
                new com.banduairlines.dto.cuenta.SolicitudCambioCorreo(" ACTUAL@example.com ")
        )).isInstanceOf(ValidacionException.class);
    }

    @Test
    void correoInvalido_fallaBeanValidation() {
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        com.banduairlines.dto.cuenta.SolicitudCambioCorreo solicitud =
                new com.banduairlines.dto.cuenta.SolicitudCambioCorreo("correo-invalido");

        assertThat(validator.validate(solicitud))
                .extracting(infraccion -> infraccion.getPropertyPath().toString())
                .contains("nuevoCorreo");
    }

    @Test
    void correoDuplicado_retornaCodigoEspecifico() {
        prepararUsuarioActual(usuario(RolUsuario.PASAJERO));
        Usuario otro = usuario(RolUsuario.PASAJERO);
        otro.setIdUsuario(2L);
        when(usuarioRepository.findByCorreo("ocupado@example.com")).thenReturn(Optional.of(otro));

        assertThatThrownBy(() -> servicio.solicitar(
                new com.banduairlines.dto.cuenta.SolicitudCambioCorreo("ocupado@example.com")
        ))
                .isInstanceOf(ConflictoException.class)
                .extracting("codigo")
                .isEqualTo("CORREO_YA_REGISTRADO");
    }

    @Test
    void confirmacionCorrecta_actualizaCorreoEInvalidaCodigo() {
        Usuario usuario = usuario(RolUsuario.PASAJERO);
        prepararUsuarioActual(usuario);
        com.banduairlines.model.SolicitudCambioCorreo solicitud = solicitudVigente("482916");
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(12L, 1L))
                .thenReturn(Optional.of(solicitud));

        RespuestaUsuario respuesta = servicio.confirmar(
                12L,
                new ConfirmacionCambioCorreo("482916")
        );

        assertThat(usuario.getCorreo()).isEqualTo("nuevo@example.com");
        assertThat(solicitud.getFechaConfirmacion()).isEqualTo(AHORA);
        assertThat(solicitud.getCodigoHash()).isNull();
        assertThat(respuesta.correo()).isEqualTo("nuevo@example.com");
        verify(usuarioRepository).saveAndFlush(usuario);
        verify(solicitudRepository).save(solicitud);
    }

    @Test
    void codigoIncorrecto_esRechazado() {
        prepararSolicitudParaConfirmar(solicitudVigente("482916"));

        assertThatThrownBy(() -> servicio.confirmar(
                12L, new ConfirmacionCambioCorreo("000000")
        ))
                .isInstanceOf(ReglaNegocioException.class)
                .extracting("codigo")
                .isEqualTo("CODIGO_INCORRECTO");
    }

    @Test
    void codigoVencido_retorna410DeDominio() {
        com.banduairlines.model.SolicitudCambioCorreo solicitud = solicitudVigente("482916");
        solicitud.setFechaExpiracion(AHORA.minusSeconds(1));
        prepararSolicitudParaConfirmar(solicitud);

        assertThatThrownBy(() -> servicio.confirmar(
                12L, new ConfirmacionCambioCorreo("482916")
        ))
                .isInstanceOf(RecursoVencidoException.class)
                .extracting("codigo")
                .isEqualTo("CODIGO_VENCIDO");
    }

    @Test
    void solicitudCancelada_noPuedeUsarse() {
        com.banduairlines.model.SolicitudCambioCorreo solicitud = solicitudVigente("482916");
        solicitud.setFechaCancelacion(AHORA.minusSeconds(10));
        solicitud.setCodigoHash(null);
        prepararSolicitudParaConfirmar(solicitud);

        assertThatThrownBy(() -> servicio.confirmar(
                12L, new ConfirmacionCambioCorreo("482916")
        )).isInstanceOf(ReglaNegocioException.class);
    }

    @Test
    void solicitudYaConfirmada_noPuedeUsarse() {
        com.banduairlines.model.SolicitudCambioCorreo solicitud = solicitudVigente("482916");
        solicitud.setFechaConfirmacion(AHORA.minusSeconds(10));
        solicitud.setCodigoHash(null);
        prepararSolicitudParaConfirmar(solicitud);

        assertThatThrownBy(() -> servicio.confirmar(
                12L, new ConfirmacionCambioCorreo("482916")
        ))
                .isInstanceOf(ReglaNegocioException.class)
                .extracting("codigo")
                .isEqualTo("CODIGO_INCORRECTO");
    }

    @Test
    void solicitudInexistenteODeOtroUsuario_retornaNoEncontrada() {
        prepararUsuarioActual(usuario(RolUsuario.PASAJERO));
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(99L, 1L))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> servicio.confirmar(
                99L, new ConfirmacionCambioCorreo("482916")
        ))
                .isInstanceOf(RecursoNoEncontradoException.class)
                .extracting("codigo")
                .isEqualTo("SOLICITUD_NO_ENCONTRADA");
    }

    @Test
    void correoRegistradoDespuesDeSolicitud_impideConfirmacion() {
        prepararSolicitudParaConfirmar(solicitudVigente("482916"));
        Usuario otro = usuario(RolUsuario.PASAJERO);
        otro.setIdUsuario(2L);
        when(usuarioRepository.findByCorreo("nuevo@example.com")).thenReturn(Optional.of(otro));

        assertThatThrownBy(() -> servicio.confirmar(
                12L, new ConfirmacionCambioCorreo("482916")
        )).isInstanceOf(ConflictoException.class);
    }

    @Test
    void cancelacionConservaCorreoEInvalidaCodigo() {
        Usuario usuario = usuario(RolUsuario.PASAJERO);
        prepararUsuarioActual(usuario);
        com.banduairlines.model.SolicitudCambioCorreo solicitud = solicitudVigente("482916");
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(12L, 1L))
                .thenReturn(Optional.of(solicitud));

        servicio.cancelar(12L);

        assertThat(usuario.getCorreo()).isEqualTo("actual@example.com");
        assertThat(solicitud.getCodigoHash()).isNull();
        assertThat(solicitud.getFechaCancelacion()).isEqualTo(AHORA);
    }

    @Test
    void cancelacionDeSolicitudInexistenteODeOtroUsuario_retornaNoEncontrada() {
        prepararUsuarioActual(usuario(RolUsuario.PASAJERO));
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(99L, 1L))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> servicio.cancelar(99L))
                .isInstanceOf(RecursoNoEncontradoException.class)
                .extracting("codigo")
                .isEqualTo("SOLICITUD_NO_ENCONTRADA");
    }

    @Test
    void cancelacionRepetida_esIdempotente() {
        prepararUsuarioActual(usuario(RolUsuario.PASAJERO));
        com.banduairlines.model.SolicitudCambioCorreo solicitud = solicitudVigente("482916");
        solicitud.setFechaCancelacion(AHORA.minusSeconds(10));
        solicitud.setCodigoHash(null);
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(12L, 1L))
                .thenReturn(Optional.of(solicitud));

        servicio.cancelar(12L);

        verify(solicitudRepository, never()).save(any());
    }

    @Test
    void superadminYUsuarioNoAutenticado_sonRechazados() {
        prepararUsuarioActual(usuario(RolUsuario.SUPERADMIN));

        assertThatThrownBy(() -> servicio.solicitar(
                new com.banduairlines.dto.cuenta.SolicitudCambioCorreo("nuevo@example.com")
        )).isInstanceOf(AccessDeniedException.class);

        when(usuarioActual.exigirId()).thenThrow(
                new AuthenticationCredentialsNotFoundException("Sin sesion")
        );
        assertThatThrownBy(() -> servicio.cancelar(12L))
                .isInstanceOf(AuthenticationCredentialsNotFoundException.class);
        verify(solicitudRepository, never()).delete(any());
    }

    private void prepararUsuarioActual(Usuario usuario) {
        when(usuarioRepository.findById(1L)).thenReturn(Optional.of(usuario));
    }

    private void prepararSolicitudParaConfirmar(
            com.banduairlines.model.SolicitudCambioCorreo solicitud
    ) {
        prepararUsuarioActual(solicitud.getUsuario());
        when(solicitudRepository.findByIdSolicitudAndUsuario_IdUsuario(12L, 1L))
                .thenReturn(Optional.of(solicitud));
    }

    private Usuario usuario(RolUsuario rol) {
        Usuario usuario = Usuario.builder()
                .idUsuario(1L)
                .correo("actual@example.com")
                .nombres("Valentina")
                .apellidos("Rojas")
                .contrasenaHash("hash")
                .rol(rol)
                .activo(true)
                .build();
        if (rol == RolUsuario.PASAJERO) {
            CuentaFidelizacion cuenta = CuentaFidelizacion.builder()
                    .usuario(usuario)
                    .saldoMillas(0)
                    .nivel(Nivel.BRONCE)
                    .build();
            usuario.setCuentaFidelizacion(cuenta);
        }
        return usuario;
    }

    private com.banduairlines.model.SolicitudCambioCorreo solicitudVigente(String codigo) {
        return com.banduairlines.model.SolicitudCambioCorreo.builder()
                .idSolicitud(12L)
                .usuario(usuario(RolUsuario.PASAJERO))
                .nuevoCorreo("nuevo@example.com")
                .codigoHash(passwordEncoder.encode(codigo))
                .fechaCreacion(AHORA.minusSeconds(60))
                .fechaExpiracion(AHORA.plusSeconds(600))
                .build();
    }
}
