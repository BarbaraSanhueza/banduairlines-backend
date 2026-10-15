
package com.banduairlines.repository;

import com.banduairlines.model.CredencialRenovacion;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CredencialRenovacionRepository
        extends JpaRepository<CredencialRenovacion, Long> {

    // Busca una credencial utilizando el hash del refresh token.
    Optional<CredencialRenovacion> findByTokenHash( String tokenHash );

    // Obtiene las credenciales que no han sido revocadas
    // y que pertenecen a un usuario especifico.
    List<CredencialRenovacion>
    findByUsuario_IdAndFechaRevocacionIsNull( Long idUsuario );
}
