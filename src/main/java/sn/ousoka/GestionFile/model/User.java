package sn.ousoka.GestionFile.model;

import jakarta.persistence.*;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String prenom;
    private String nom;
    private String numeroTel;
    private String password;

    @Enumerated(EnumType.STRING)
    private Role role;

    @ManyToOne
    @JoinColumn(name = "service_id", nullable = true)
    private OKService service;

    @ManyToOne
    @JoinColumn(name = "location_id", nullable = true)
    private Location location;

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    

    public String getPrenom() { return prenom; }
    public void setPrenom(String prenom) { this.prenom = prenom; }

    public String getNom() { return nom; }
    public void setNom(String nom) { this.nom = nom; }

    public String getNumeroTel() { return numeroTel; }
    public void setNumeroTel(String numeroTel) { this.numeroTel = numeroTel; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public Role getRole() { return role; }
    public void setRole(Role role) { this.role = role; }

    public OKService getService() { return service; }
    public void setService(OKService service) { this.service = service; }

    public Location getLocation() { return location; }
    public void setLocation(Location location) { this.location = location; }

    public Long getLocationId() { 
        return location != null ? location.getId() : null; 
    }

    public Long getServiceId() { 
        return service != null ? service.getId() : null; 
    }


    // Override toString() method
    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", prenom='" + prenom + '\'' +
                ", nom='" + nom + '\'' +
                ", numeroTel='" + numeroTel + '\'' +
                '}';
    }
}
