package sn.ousoka.GestionFile.repository;

import sn.ousoka.GestionFile.model.Location;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LocationRepository extends JpaRepository<Location, Integer> {
}
