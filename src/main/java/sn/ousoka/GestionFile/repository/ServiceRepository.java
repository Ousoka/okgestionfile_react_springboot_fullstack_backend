package sn.ousoka.GestionFile.repository;
import java.util.List;

import sn.ousoka.GestionFile.model.OKService;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceRepository extends JpaRepository<OKService, Long> {
}
