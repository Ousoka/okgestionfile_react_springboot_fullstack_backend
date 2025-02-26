package sn.ousoka.GestionFile.controller;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sn.ousoka.GestionFile.model.OKService;
import sn.ousoka.GestionFile.model.Location;
import sn.ousoka.GestionFile.model.Ticket;
import sn.ousoka.GestionFile.model.User;
import sn.ousoka.GestionFile.model.Role;
import sn.ousoka.GestionFile.model.TicketStatus;
import sn.ousoka.GestionFile.service.GestionFileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Optional;
import java.util.ArrayList;
import java.util.List;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import sn.ousoka.GestionFile.model.QueueInfo;
import sn.ousoka.GestionFile.repository.ServiceRepository;
import sn.ousoka.GestionFile.repository.LocationRepository;
import sn.ousoka.GestionFile.repository.TicketRepository;
import sn.ousoka.GestionFile.repository.UserRepository;
// import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "https://okgestionfile-react-springboot-fullstack.onrender.com")
public class GestionFileController {

    @Autowired
    private GestionFileService gestionFileService;

    @Autowired
    private LocationRepository locationRepository;

    @Autowired
    private ServiceRepository serviceRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private TicketRepository ticketRepository;

    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    private AuthenticationManager authenticationManager;

    private static final Logger log = LoggerFactory.getLogger(GestionFileController.class);

    public GestionFileController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/")
    public ResponseEntity<String> index() {
        return new ResponseEntity<>("home", HttpStatus.OK);
    }

    @GetMapping("/login")
    public ResponseEntity<String> login_page() {
        return new ResponseEntity<>("login", HttpStatus.OK);
    }

    // @PostMapping("/login")
    // public ResponseEntity<?> login(@RequestParam String numeroTel, 
    //                                @RequestParam String password, 
    //                                HttpSession session) {
    //     log.debug("Tentative de connexion avec le téléphone : [{}]", numeroTel);
    //     System.out.println("Attempting login with phone number: " + numeroTel);

    //     try {
    //         Authentication authentication = authenticationManager.authenticate(
    //             new UsernamePasswordAuthenticationToken(numeroTel, password)
    //         );
    //         SecurityContextHolder.getContext().setAuthentication(authentication);

    //         UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    //         String numero = userDetails.getUsername();

    //         System.out.println("Authenticated user phone number: " + numero);

    //         User user = userRepository.findByNumeroTel(numero)
    //                 .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

    //         session.setAttribute("userId", user.getId());
    //         session.setAttribute("username", user.getNom());
    //         session.setAttribute("prenom", user.getPrenom());
    //         session.setAttribute("numeroTel", user.getNumeroTel());
    //         session.setAttribute("role", user.getRole().name());

    //         log.info("Utilisateur [{}] connecté avec rôle [{}]", user.getNom(), user.getRole().name());
    //         log.info("Nom stocké en session: {}", session.getAttribute("username"));

    //         switch (user.getRole().name()) {
    //             case "CLIENT":
    //                 return new ResponseEntity<>("redirect:/client_home", HttpStatus.OK);
    //             case "AGENT":
    //                 return new ResponseEntity<>("redirect:/agent_home", HttpStatus.OK);
    //             case "ADMIN":
    //                 return new ResponseEntity<>("redirect:/admin", HttpStatus.OK);
    //             default:
    //                 return new ResponseEntity<>("redirect:/home", HttpStatus.OK);
    //         }
    //     } catch (BadCredentialsException e) {
    //         log.error("Échec d'authentification pour le téléphone : {}", numeroTel, e);
    //         System.out.println("Authentication failed for phone number: " + numeroTel);
    //         return new ResponseEntity<>("Numéro de téléphone ou mot de passe invalide.", HttpStatus.UNAUTHORIZED);
    //     }
    // }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam String numeroTel, 
                                @RequestParam String password, 
                                HttpSession session) {
        log.debug("Tentative de connexion avec le téléphone : [{}]", numeroTel);
        System.out.println("Attempting login with phone number: " + numeroTel);

        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(numeroTel, password)
            );

            // Store authentication in SecurityContextHolder
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // Ensure session is created and linked
            session.setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String numero = userDetails.getUsername();

            User user = userRepository.findByNumeroTel(numero)
                    .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

            // Store user info in session
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getNom());
            session.setAttribute("prenom", user.getPrenom());
            session.setAttribute("numeroTel", user.getNumeroTel());
            session.setAttribute("role", user.getRole().name());

            log.info("Utilisateur [{}] connecté avec rôle [{}]", user.getNom(), user.getRole().name());

            // Create a JSON response
            LoginResponse loginResponse = new LoginResponse(
                user.getId(),
                user.getNom(),
                user.getPrenom(),
                user.getNumeroTel(),
                user.getRole().name()
            );

            return new ResponseEntity<>(loginResponse, HttpStatus.OK);

        } catch (BadCredentialsException e) {
            log.error("Échec d'authentification pour le téléphone : {}", numeroTel, e);
            return new ResponseEntity<>(new ErrorResponse("Numéro de téléphone ou mot de passe invalide."), HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            log.error("Erreur lors de la connexion : {}", e.getMessage());
            return new ResponseEntity<>(new ErrorResponse("Erreur interne du serveur."), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // Inner classes for response objects
    private static class LoginResponse {
        private final Long userId;
        private final String nom;
        private final String prenom;
        private final String numeroTel;
        private final String role;

        public LoginResponse(Long userId, String nom, String prenom, String numeroTel, String role) {
            this.userId = userId;
            this.nom = nom;
            this.prenom = prenom;
            this.numeroTel = numeroTel;
            this.role = role;
        }

        public Long getUserId() { return userId; }
        public String getNom() { return nom; }
        public String getPrenom() { return prenom; }
        public String getNumeroTel() { return numeroTel; }
        public String getRole() { return role; }
    }

    private static class ErrorResponse {
        private final String message;

        public ErrorResponse(String message) {
            this.message = message;
        }

        public String getMessage() { return message; }
    }

    @GetMapping("/home")
    public ResponseEntity<String> home() {
        return new ResponseEntity<>("home", HttpStatus.OK);
    }

    @GetMapping("/client_home")
    public ResponseEntity<?> clientHome(HttpSession session) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String numeroTel;

        if (auth != null && auth.getPrincipal() instanceof UserDetails) {
            numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            numeroTel = (String) session.getAttribute("numeroTel");
        }

        Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);
        if (userOptional.isPresent()) {
            return new ResponseEntity<>(userOptional.get(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>("User not found", HttpStatus.NOT_FOUND);
        }
    }

    // @GetMapping("/logout")
    // public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response) {
    //     SecurityContextHolder.clearContext();
    //     request.getSession().invalidate();
    //     return new ResponseEntity<>("redirect:/", HttpStatus.OK);
    // }

    @GetMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        // Clear security context and invalidate session
        SecurityContextHolder.clearContext();
        HttpSession session = request.getSession(false); // Get session if it exists
        if (session != null) {
            session.invalidate();
        }

        // Return a JSON response instead of a redirect string
        return new ResponseEntity<>(new LogoutResponse("Déconnexion réussie"), HttpStatus.OK);
    }

    // Inner class for logout response
    private static class LogoutResponse {
        private final String message;

        public LogoutResponse(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }

    @GetMapping("/admin_users")
    public ResponseEntity<?> create_user_page() {
        List<User> admins = userRepository.findByRole(Role.ADMIN);
        List<User> agents = userRepository.findByRole(Role.AGENT);
        List<User> clients = userRepository.findByRole(Role.CLIENT);
        List<OKService> services = serviceRepository.findAll();
        List<Location> locations = locationRepository.findAll();

        return new ResponseEntity<>(new AdminUsersResponse(admins, agents, clients, services, locations), HttpStatus.OK);
    }

    @PostMapping("/createUser")
    public ResponseEntity<?> createUser(
            @RequestParam String prenom,
            @RequestParam String nom,
            @RequestParam String numeroTel,
            @RequestParam String password,
            @RequestParam Role role,
            @RequestParam(required = false) int serviceId,
            @RequestParam(required = false) int locationId) {
        String hashedPassword = passwordEncoder.encode(password);

        User newUser = new User();
        newUser.setPrenom(prenom);
        newUser.setNom(nom);
        newUser.setNumeroTel(numeroTel);
        newUser.setPassword(hashedPassword);
        newUser.setRole(role);

        if (role == Role.AGENT) {
            Optional<OKService> service = serviceRepository.findById(serviceId);
            Optional<Location> location = locationRepository.findById(locationId);
            service.ifPresent(newUser::setService);
            location.ifPresent(newUser::setLocation);
        }

        userRepository.save(newUser);

        List<User> admins = userRepository.findByRole(Role.ADMIN);
        List<User> agents = userRepository.findByRole(Role.AGENT);
        List<User> clients = userRepository.findByRole(Role.CLIENT);
        List<OKService> services = serviceRepository.findAll();
        List<Location> locations = locationRepository.findAll();

        return new ResponseEntity<>(new AdminUsersResponse(admins, agents, clients, services, locations), HttpStatus.OK);
    }

    @GetMapping("/deleteUser/{id}")
    public ResponseEntity<?> deleteUser(@PathVariable("id") int id) {
        userRepository.deleteById(id);

        List<User> admins = userRepository.findByRole(Role.ADMIN);
        List<User> agents = userRepository.findByRole(Role.AGENT);
        List<User> clients = userRepository.findByRole(Role.CLIENT);
        List<OKService> services = serviceRepository.findAll();
        List<Location> locations = locationRepository.findAll();

        return new ResponseEntity<>(new AdminUsersResponse(admins, agents, clients, services, locations), HttpStatus.OK);
    }

    // @GetMapping("/client_obtain_ticket")
    // public ResponseEntity<?> clientObtainTicketPage() {
    //     try {
    //         List<OKService> services = gestionFileService.getAllServices();
    //         List<Location> locations = gestionFileService.getAllLocations();

    //         if (services == null || locations == null) {
    //             log.error("Donnees {Services ou localisations} sont null.");
    //             throw new IllegalStateException("Donnees {Services ou localisations} sont indisponibles.");
    //         }

    //         return new ResponseEntity<>(new ClientObtainTicketResponse(services, locations), HttpStatus.OK);
    //     } catch (Exception e) {
    //         log.error("Error in clientPage method: {}", e.getMessage());
    //         e.printStackTrace();
    //         return new ResponseEntity<>("Erreurs lors de la recup des services et localisations.", HttpStatus.INTERNAL_SERVER_ERROR);
    //     }
    // }

    @GetMapping("/client_obtain_ticket")
    public ResponseEntity<?> clientObtainTicketPage() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth == null || !auth.isAuthenticated()) {
                log.error("User is not authenticated.");
                return new ResponseEntity<>("User is not authenticated.", HttpStatus.UNAUTHORIZED);
            }

            log.info("User [{}] is authenticated.", auth.getName());

            List<OKService> services = gestionFileService.getAllServices();
            List<Location> locations = gestionFileService.getAllLocations();

            if (services == null || locations == null) {
                log.error("Donnees {Services ou localisations} sont null.");
                throw new IllegalStateException("Donnees {Services ou localisations} sont indisponibles.");
            }

            return new ResponseEntity<>(new ClientObtainTicketResponse(services, locations), HttpStatus.OK);
        } catch (Exception e) {
            log.error("Error in clientObtainTicketPage method: {}", e.getMessage());
            return new ResponseEntity<>("Erreurs lors de la recup des services et localisations.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // @GetMapping("/client_view_tickets") 
    // public ResponseEntity<?> clientViewTicketsPage(HttpSession session) {
    //     try {
    //         // log.info("Session ID: {}", session.getId());
    //         Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    //         if (auth == null || !auth.isAuthenticated()) {
    //             log.error("User is not authenticated.");
    //             return new ResponseEntity<>("User is not authenticated.", HttpStatus.UNAUTHORIZED);
    //         }

    //         log.info("User [{}] is authenticated to view their tickets", auth.getName());

    //         String numeroTel;

    //         if (auth != null && auth.getPrincipal() instanceof UserDetails) {
    //             numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
    //         } else {
    //             numeroTel = (String) session.getAttribute("numeroTel");
    //         }

    //         User user = userRepository.findByNumeroTel(numeroTel)
    //                 .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

    //         Long userIdLong = (Long) user.getId();

    //         if (userIdLong == null) {
    //             return new ResponseEntity<>("User not logged in.", HttpStatus.UNAUTHORIZED);
    //         }

    //         int userId = userIdLong.intValue();

    //         List<Ticket> tickets = ticketRepository.findByUserId(userId);
    //         List<OKService> services = gestionFileService.getAllServices();
    //         List<Location> locations = gestionFileService.getAllLocations();

    //         if (services == null || locations == null) {
    //             log.error("Data {Services or locations} are null.");
    //             throw new IllegalStateException("Data {Services or locations} are unavailable.");
    //         }

    //         return new ResponseEntity<>(new ClientViewTicketsResponse(tickets, services, locations), HttpStatus.OK);
    //     } catch (Exception e) {
    //         log.error("Error in clientViewTicketsPage method: {}", e.getMessage());
    //         e.printStackTrace();
    //         return new ResponseEntity<>("Error retrieving services, locations, or tickets.", HttpStatus.INTERNAL_SERVER_ERROR);
    //     }
    // }

    // @GetMapping("/client_view_tickets")
    // public ResponseEntity<?> clientViewTicketsPage(HttpSession session) {
    //     log.info("Session ID: {}", session.getId());
    //     Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    //     if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
    //         log.error("No authenticated user found. Session attributes: {}", Collections.list(session.getAttributeNames()));
    //         return new ResponseEntity<>("User is not authenticated.", HttpStatus.UNAUTHORIZED);
    //     }
    //     String numeroTel = auth.getName();
    //     log.info("Authenticated user: {}", numeroTel);

    //     User user = userRepository.findByNumeroTel(numeroTel)
    //             .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));
    //     Long userIdLong = user.getId();
    //     int userId = userIdLong.intValue();

    //     List<Ticket> tickets = ticketRepository.findByUserId(userId);
    //     List<OKService> services = gestionFileService.getAllServices();
    //     List<Location> locations = gestionFileService.getAllLocations();

    //     // Log for debugging
    //     log.info("Tickets: {}", tickets);
    //     log.info("Services: {}", services);
    //     log.info("Locations: {}", locations);

    //     return new ResponseEntity<>(new ClientViewTicketsResponse(tickets, services, locations), HttpStatus.OK);
    // }

    @GetMapping("/client_view_tickets")
    public ResponseEntity<?> clientViewTicketsPage(HttpSession session) {
        log.info("Session ID: {}", session.getId());
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || auth instanceof AnonymousAuthenticationToken) {
            log.error("No authenticated user found. Session attributes: {}", Collections.list(session.getAttributeNames()));
            return new ResponseEntity<>("User is not authenticated.", HttpStatus.UNAUTHORIZED);
        }
        String numeroTel = auth.getName();
        log.info("Authenticated user: {}", numeroTel);

        try {
            User user = userRepository.findByNumeroTel(numeroTel)
                    .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));
            Long userIdLong = user.getId();
            int userId = userIdLong.intValue();

            List<Ticket> tickets = ticketRepository.findByUserId(userId);
            List<OKService> services = gestionFileService.getAllServices();
            List<Location> locations = gestionFileService.getAllLocations();

            // Detailed logging
            for (Ticket ticket : tickets) {
                log.info("Ticket details: id={}, ticketNumber={}, positionInQueue={}, status={}, serviceId={}, locationId={}",
                    ticket.getId(), ticket.getTicketNumber(), ticket.getPositionInQueue(), ticket.getStatus(),
                    ticket.getService() != null ? ticket.getService().getId() : null,
                    ticket.getLocation() != null ? ticket.getLocation().getId() : null);
            }
            log.info("Services: {}", services);
            log.info("Locations: {}", locations);

            ClientViewTicketsResponse response = new ClientViewTicketsResponse(tickets, services, locations);
            log.info("Response prepared: tickets.size={}, services.size={}, locations.size={}",
                    response.getTickets().size(), response.getServices().size(), response.getLocations().size());

            return new ResponseEntity<>(response, HttpStatus.OK);
        } catch (Exception e) {
            log.error("Error processing client_view_tickets: {}", e.getMessage(), e);
            return new ResponseEntity<>("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/client")
    public ResponseEntity<?> clientPage() {
        try {
            List<OKService> services = gestionFileService.getAllServices();
            List<Location> locations = gestionFileService.getAllLocations();

            if (services == null || locations == null) {
                log.error("Donnees {Services ou localisations} sont null.");
                throw new IllegalStateException("Donnees {Services ou localisations} sont indisponibles.");
            }
 
            return new ResponseEntity<>(new ClientPageResponse(services, locations), HttpStatus.OK);
        } catch (Exception e) {
            log.error("Error in clientPage method: {}", e.getMessage());
            e.printStackTrace();
            return new ResponseEntity<>("Erreurs lors de la recup des services et localisations.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @PostMapping("/client_ticket")
    public ResponseEntity<?> createTicket(@RequestParam int serviceId, @RequestParam int locationId, HttpSession session) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            String numeroTel;

            if (auth != null && auth.getPrincipal() instanceof UserDetails) {
                numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
            } else {
                numeroTel = (String) session.getAttribute("numeroTel");
            }

            User user = userRepository.findByNumeroTel(numeroTel)
                    .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

            OKService service = gestionFileService.getServiceById(serviceId)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid service ID"));
            Location location = gestionFileService.getLocationById(locationId)
                    .orElseThrow(() -> new IllegalArgumentException("Invalid location ID"));

            Ticket newTicket = gestionFileService.createTicket(service, location, user);

            Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
            Ticket currentTicket = currentTicketOptional.orElse(null);

            int peopleAhead = gestionFileService.getPeopleAhead(newTicket.getId(), serviceId, locationId);

            return new ResponseEntity<>(new ClientTicketResponse(newTicket, currentTicket, service, location, peopleAhead), HttpStatus.OK);
        } catch (Exception e) {
            log.error("Error creating ticket: {}", e.getMessage());
            return new ResponseEntity<>("There was an error creating the ticket.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/agent/ticket/status")
    public ResponseEntity<?> updateTicketStatus(@RequestParam(required = false) Integer ticketId,
                                                @RequestParam(required = false) Integer serviceId,
                                                @RequestParam(required = false) Integer locationId,
                                                @RequestParam String action,
                                                HttpSession session) {
        String numeroTel = null;

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getPrincipal() instanceof UserDetails) {
            numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            numeroTel = (String) session.getAttribute("numeroTel");
        }

        Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);
        if (!userOptional.isPresent()) {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }

        User user = userOptional.get();
        locationId = locationId == null ? user.getLocationId() : locationId;
        serviceId = serviceId == null ? user.getServiceId() : serviceId;

        if (ticketId == null || ticketId == 0) {
            return new ResponseEntity<>("Missing ticket ID.", HttpStatus.BAD_REQUEST);
        }

        try {
            gestionFileService.updateTicketStatus(ticketId, action);

            List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
            Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
            Ticket currentTicket = currentTicketOptional.orElse(null);

            return new ResponseEntity<>(new AgentTicketStatusResponse(tickets, currentTicket, serviceId, locationId, user), HttpStatus.OK);
        } catch (Exception e) {
            log.error("Error updating ticket status: {}", e.getMessage());
            return new ResponseEntity<>("Unable to update ticket status: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/agent")
    public ResponseEntity<?> agentPage() {
        return new ResponseEntity<>(new AgentPageResponse(gestionFileService.getAllServices(), gestionFileService.getAllLocations()), HttpStatus.OK);
    }

    @GetMapping("/agent_home")
    public ResponseEntity<?> agentHomePage(HttpSession session) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String numeroTel = null;

        if (auth != null && auth.getPrincipal() instanceof UserDetails) {
            numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            numeroTel = (String) session.getAttribute("numeroTel");
        }

        Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);

        if (userOptional.isPresent()) {
            User user = userOptional.get();
            Integer locationId = user.getLocationId();
            Integer serviceId = user.getServiceId();

            List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
            Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
            Ticket currentTicket = currentTicketOptional.orElse(null);

            return new ResponseEntity<>(new AgentHomePageResponse(tickets, currentTicket, serviceId, locationId, user, gestionFileService.getAllServices(), gestionFileService.getAllLocations()), HttpStatus.OK);
        } else {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/agent/tickets")
    public ResponseEntity<?> viewTickets(@RequestParam(required = false) Integer serviceId,
                                         @RequestParam(required = false) Integer locationId) {
        if (serviceId == null || locationId == null) {
            log.warn("Missing serviceId or locationId");
            return new ResponseEntity<>("Please select both a service and a location.", HttpStatus.BAD_REQUEST);
        }

        List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
        Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
        Ticket currentTicket = currentTicketOptional.orElse(null);

        return new ResponseEntity<>(new AgentTicketsResponse(tickets, currentTicket, gestionFileService.getAllServices(), gestionFileService.getAllLocations()), HttpStatus.OK);
    }

    @GetMapping("/ticket/{ticketId}")
    public ResponseEntity<?> viewTicket(@PathVariable int ticketId) {
        Ticket ticket = ticketRepository.findById(ticketId)
                .orElseThrow(() -> new IllegalArgumentException("Invalid ticket ID"));

        Optional<Ticket> currentTicket = gestionFileService.getCurrentTicket(ticket.getService().getId(), ticket.getLocation().getId());

        return new ResponseEntity<>(new TicketResponse(ticket, currentTicket.orElse(null)), HttpStatus.OK);
    }

    @GetMapping("/admin")
    public ResponseEntity<?> adminBackoffice() {
        List<OKService> services = gestionFileService.getAllServices();
        List<Location> locations = gestionFileService.getAllLocations();

        List<QueueInfo> queueInfos = new ArrayList<>();

        for (OKService service : services) {
            for (Location location : locations) {
                QueueInfo queueInfo = gestionFileService.getQueueInfo(service, location);
                if (queueInfo != null) {
                    queueInfos.add(queueInfo);
                }
            }
        }

        return new ResponseEntity<>(new AdminBackofficeResponse(services, locations, queueInfos), HttpStatus.OK);
    }

    @GetMapping("/admin_home")
    public ResponseEntity<?> adminHomePage(HttpSession session) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String numeroTel = null;

        if (auth != null && auth.getPrincipal() instanceof UserDetails) {
            numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
        } else {
            numeroTel = (String) session.getAttribute("numeroTel");
        }

        Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);

        if (userOptional.isPresent()) {
            User user = userOptional.get();

            List<OKService> services = gestionFileService.getAllServices();
            List<Location> locations = gestionFileService.getAllLocations();

            List<QueueInfo> queueInfos = new ArrayList<>();

            for (OKService service : services) {
                for (Location location : locations) {
                    QueueInfo queueInfo = gestionFileService.getQueueInfo(service, location);
                    if (queueInfo != null) {
                        queueInfos.add(queueInfo);
                    }
                }
            }

            return new ResponseEntity<>(new AdminHomePageResponse(user, services, locations, queueInfos), HttpStatus.OK);
        } else {
            return new ResponseEntity<>("User not found.", HttpStatus.NOT_FOUND);
        }
    }

    // Inner classes for response objects
    private static class AdminUsersResponse {
        private final List<User> admins;
        private final List<User> agents;
        private final List<User> clients;
        private final List<OKService> services;
        private final List<Location> locations;

        public AdminUsersResponse(List<User> admins, List<User> agents, List<User> clients, List<OKService> services, List<Location> locations) {
            this.admins = admins;
            this.agents = agents;
            this.clients = clients;
            this.services = services;
            this.locations = locations;
        }

        public List<User> getAdmins() {
            return admins;
        }

        public List<User> getAgents() {
            return agents;
        }

        public List<User> getClients() {
            return clients;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class ClientObtainTicketResponse {
        private final List<OKService> services;
        private final List<Location> locations;

        public ClientObtainTicketResponse(List<OKService> services, List<Location> locations) {
            this.services = services;
            this.locations = locations;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class ClientViewTicketsResponse {
        private final List<Ticket> tickets;
        private final List<OKService> services;
        private final List<Location> locations;

        // public ClientViewTicketsResponse(List<Ticket> tickets, List<OKService> services, List<Location> locations) {
        //     this.tickets = tickets;
        //     this.services = services;
        //     this.locations = locations;
        // }

        public ClientViewTicketsResponse(List<Ticket> tickets, List<OKService> services, List<Location> locations) {
            this.tickets = tickets != null ? tickets : Collections.emptyList();
            this.services = services != null ? services : Collections.emptyList();
            this.locations = locations != null ? locations : Collections.emptyList();
        }

        public List<Ticket> getTickets() {
            return tickets;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class ClientPageResponse {
        private final List<OKService> services;
        private final List<Location> locations;

        public ClientPageResponse(List<OKService> services, List<Location> locations) {
            this.services = services;
            this.locations = locations;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class ClientTicketResponse {
        private final Ticket newTicket;
        private final Ticket currentTicket;
        private final OKService service;
        private final Location location;
        private final int peopleAhead;

        public ClientTicketResponse(Ticket newTicket, Ticket currentTicket, OKService service, Location location, int peopleAhead) {
            this.newTicket = newTicket;
            this.currentTicket = currentTicket;
            this.service = service;
            this.location = location;
            this.peopleAhead = peopleAhead;
        }

        public Ticket getNewTicket() {
            return newTicket;
        }

        public Ticket getCurrentTicket() {
            return currentTicket;
        }

        public OKService getService() {
            return service;
        }

        public Location getLocation() {
            return location;
        }

        public int getPeopleAhead() {
            return peopleAhead;
        }
    }

    private static class AgentTicketStatusResponse {
        private final List<Ticket> tickets;
        private final Ticket currentTicket;
        private final int serviceId;
        private final int locationId;
        private final User user;

        public AgentTicketStatusResponse(List<Ticket> tickets, Ticket currentTicket, int serviceId, int locationId, User user) {
            this.tickets = tickets;
            this.currentTicket = currentTicket;
            this.serviceId = serviceId;
            this.locationId = locationId;
            this.user = user;
        }

        public List<Ticket> getTickets() {
            return tickets;
        }

        public Ticket getCurrentTicket() {
            return currentTicket;
        }

        public int getServiceId() {
            return serviceId;
        }

        public int getLocationId() {
            return locationId;
        }

        public User getUser() {
            return user;
        }
    }

    private static class AgentPageResponse {
        private final List<OKService> services;
        private final List<Location> locations;

        public AgentPageResponse(List<OKService> services, List<Location> locations) {
            this.services = services;
            this.locations = locations;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class AgentHomePageResponse {
        private final List<Ticket> tickets;
        private final Ticket currentTicket;
        private final int serviceId;
        private final int locationId;
        private final User user;
        private final List<OKService> services;
        private final List<Location> locations;

        public AgentHomePageResponse(List<Ticket> tickets, Ticket currentTicket, int serviceId, int locationId, User user, List<OKService> services, List<Location> locations) {
            this.tickets = tickets;
            this.currentTicket = currentTicket;
            this.serviceId = serviceId;
            this.locationId = locationId;
            this.user = user;
            this.services = services;
            this.locations = locations;
        }

        public List<Ticket> getTickets() {
            return tickets;
        }

        public Ticket getCurrentTicket() {
            return currentTicket;
        }

        public int getServiceId() {
            return serviceId;
        }

        public int getLocationId() {
            return locationId;
        }

        public User getUser() {
            return user;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class AgentTicketsResponse {
        private final List<Ticket> tickets;
        private final Ticket currentTicket;
        private final List<OKService> services;
        private final List<Location> locations;

        public AgentTicketsResponse(List<Ticket> tickets, Ticket currentTicket, List<OKService> services, List<Location> locations) {
            this.tickets = tickets;
            this.currentTicket = currentTicket;
            this.services = services;
            this.locations = locations;
        }

        public List<Ticket> getTickets() {
            return tickets;
        }

        public Ticket getCurrentTicket() {
            return currentTicket;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }
    }

    private static class TicketResponse {
        private final Ticket ticket;
        private final Ticket currentTicket;

        public TicketResponse(Ticket ticket, Ticket currentTicket) {
            this.ticket = ticket;
            this.currentTicket = currentTicket;
        }

        public Ticket getTicket() {
            return ticket;
        }

        public Ticket getCurrentTicket() {
            return currentTicket;
        }
    }

    private static class AdminBackofficeResponse {
        private final List<OKService> services;
        private final List<Location> locations;
        private final List<QueueInfo> queueInfos;

        public AdminBackofficeResponse(List<OKService> services, List<Location> locations, List<QueueInfo> queueInfos) {
            this.services = services;
            this.locations = locations;
            this.queueInfos = queueInfos;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }

        public List<QueueInfo> getQueueInfos() {
            return queueInfos;
        }
    }

    private static class AdminHomePageResponse {
        private final User user;
        private final List<OKService> services;
        private final List<Location> locations;
        private final List<QueueInfo> queueInfos;

        public AdminHomePageResponse(User user, List<OKService> services, List<Location> locations, List<QueueInfo> queueInfos) {
            this.user = user;
            this.services = services;
            this.locations = locations;
            this.queueInfos = queueInfos;
        }

        public User getUser() {
            return user;
        }

        public List<OKService> getServices() {
            return services;
        }

        public List<Location> getLocations() {
            return locations;
        }

        public List<QueueInfo> getQueueInfos() {
            return queueInfos;
        }
    }
}