package sn.ousoka.GestionFile.repository;

import sn.ousoka.GestionFile.model.User;
import sn.ousoka.GestionFile.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByRole(Role role);
    Optional<User> findByNumeroTel(String numeroTel);

}
