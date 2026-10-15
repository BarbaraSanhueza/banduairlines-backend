package com.banduairlines.service;

import com.banduairlines.exception.ReglaNegocioException;
import com.banduairlines.exception.ValidacionException;
import com.banduairlines.model.ConfiguracionNivel;
import com.banduairlines.model.Usuario;
import com.banduairlines.model.enums.Nivel;
import com.banduairlines.model.enums.RolUsuario;
import com.banduairlines.service.impl.GestionNivelServiceImpl;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GestionNivelServiceImplTest {

    private final GestionNivelServiceImpl servicio =
            new GestionNivelServiceImpl("1000", "5000");

    @Test
    void determinaBroncePlataYOroConUmbralesConfigurados() {
        assertThat(servicio.determinarNivel(0)).isEqualTo(Nivel.BRONCE);
        assertThat(servicio.determinarNivel(999)).isEqualTo(Nivel.BRONCE);
        assertThat(servicio.determinarNivel(1000)).isEqualTo(Nivel.PLATA);
        assertThat(servicio.determinarNivel(4999)).isEqualTo(Nivel.PLATA);
        assertThat(servicio.determinarNivel(5000)).isEqualTo(Nivel.ORO);
        assertThat(servicio.determinarNivel(Long.MAX_VALUE)).isEqualTo(Nivel.ORO);
    }

    @Test
    void configuracionExponeMillasYMultiplicadoresDelContrato() {
        ConfiguracionNivel bronce = servicio.obtenerConfiguracion(Nivel.BRONCE);
        ConfiguracionNivel plata = servicio.obtenerConfiguracion(Nivel.PLATA);
        ConfiguracionNivel oro = servicio.obtenerConfiguracion(Nivel.ORO);

        assertThat(bronce.millasMinimas()).isZero();
        assertThat(bronce.multiplicadorPuntos()).isEqualByComparingTo(BigDecimal.ONE);
        assertThat(plata.millasMinimas()).isEqualTo(1000);
        assertThat(plata.multiplicadorPuntos()).isEqualByComparingTo("1.2");
        assertThat(oro.millasMinimas()).isEqualTo(5000);
        assertThat(oro.multiplicadorPuntos()).isEqualByComparingTo("1.5");
    }

    @Test
    void canjeDePuntosNoIntervieneEnCalculoDelNivel() {
        Nivel antesDelCanje = servicio.determinarNivel(5200);
        Nivel despuesDelCanje = servicio.determinarNivel(5200);

        assertThat(despuesDelCanje).isEqualTo(antesDelCanje).isEqualTo(Nivel.ORO);
    }

    @Test
    void millasNegativasSonInvalidas() {
        assertThatThrownBy(() -> servicio.determinarNivel(-1))
                .isInstanceOf(ValidacionException.class);
    }

    @Test
    void umbralesNoDefinidosNoSeInventan() {
        GestionNivelServiceImpl sinConfigurar = new GestionNivelServiceImpl("", "");

        assertThatThrownBy(() -> sinConfigurar.determinarNivel(1000))
                .isInstanceOf(ReglaNegocioException.class)
                .extracting("codigo")
                .isEqualTo("CONFIGURACION_NIVELES_INCOMPLETA");
    }

    @Test
    void administradoresYSuperadminNoTienenCuentaDeNivelPorDefecto() {
        Usuario administrador = Usuario.builder().rol(RolUsuario.ADMINISTRADOR).build();
        Usuario superadmin = Usuario.builder().rol(RolUsuario.SUPERADMIN).build();

        assertThat(administrador.getCuentaFidelizacion()).isNull();
        assertThat(superadmin.getCuentaFidelizacion()).isNull();
    }
}
