// package sn.ousoka.GestionFile.controller;
// import org.slf4j.Logger;
// import org.slf4j.LoggerFactory;
// import sn.ousoka.GestionFile.model.OKService;
// import sn.ousoka.GestionFile.model.Location;
// import sn.ousoka.GestionFile.model.Ticket;
// import sn.ousoka.GestionFile.model.User;
// import sn.ousoka.GestionFile.model.Role;
// import sn.ousoka.GestionFile.model.TicketStatus;
// import sn.ousoka.GestionFile.service.GestionFileService;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.stereotype.Controller;
// import org.springframework.ui.Model;
// import org.springframework.web.bind.annotation.*;
// import java.util.Optional;
// import java.util.ArrayList; 
// import java.util.List; 
// import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
// import org.springframework.web.servlet.mvc.support.RedirectAttributes;
// import javax.servlet.http.HttpServletRequest;
// import javax.servlet.http.HttpServletResponse;
// import org.springframework.security.core.userdetails.UsernameNotFoundException;
// import sn.ousoka.GestionFile.model.QueueInfo; 

// import sn.ousoka.GestionFile.repository.ServiceRepository;
// import sn.ousoka.GestionFile.repository.LocationRepository;
// import sn.ousoka.GestionFile.repository.TicketRepository;
// import sn.ousoka.GestionFile.repository.UserRepository;

// // import javax.servlet.http.HttpSession;
// import jakarta.servlet.http.HttpSession;

// import org.springframework.security.core.userdetails.UserDetails;

// import org.springframework.security.authentication.AuthenticationManager;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.security.authentication.BadCredentialsException;



// @Controller
// @RequestMapping("/")
// public class GestionFileController {
//     @Autowired
//     private GestionFileService gestionFileService;

//     @Autowired
//     private LocationRepository locationRepository;

//     @Autowired
//     private ServiceRepository serviceRepository;

//     @Autowired
//     private UserRepository userRepository;

//     @Autowired
//     private TicketRepository ticketRepository;

        
//     @Autowired
//     private BCryptPasswordEncoder passwordEncoder;
    
//     // private final AuthenticationManager authenticationManager;
//     private AuthenticationManager authenticationManager;

//     private static final Logger log = LoggerFactory.getLogger(GestionFileController.class);
    
//     public GestionFileController(AuthenticationManager authenticationManager) {
//         this.authenticationManager = authenticationManager;
//     }


// //     @GetMapping("/")
// //     public String index() {
// //         return "home";
// //     }

// //     @GetMapping("/login")
// //     public String login_page() {
// //         return "login";
// //     }

// // @PostMapping("/login")
// // public String login(@RequestParam String numeroTel, @RequestParam String password, Model model) {
// //     log.debug("Received login attempt with phone: [{}]", numeroTel);
// //     log.debug("Received password: [{}]", password);

// //     try {
// //         Authentication authentication = authenticationManager.authenticate(
// //             new UsernamePasswordAuthenticationToken(numeroTel, password)
// //         );
// //         SecurityContextHolder.getContext().setAuthentication(authentication);
// //         return "redirect:/client";
// //     } catch (BadCredentialsException e) {
// //         log.error("Authentication failed for phone number: {}", numeroTel, e);
// //         model.addAttribute("error", "Invalid phone number or password.");
// //         return "login";
// //     }
// // }


//     @GetMapping("/")
//     public String index() {
//         return "home";
//     }

//     @GetMapping("/login")
//     public String login_page() {
//         return "login";
//     }

// // @PostMapping("/login")
// // public String login(@RequestParam String numeroTel, @RequestParam String password, Model model) {
// //     log.debug("Login attempt with phone: [{}]", numeroTel);

// //     try {
// //         Authentication authentication = authenticationManager.authenticate(
// //             new UsernamePasswordAuthenticationToken(numeroTel, password)
// //         );

// //         SecurityContextHolder.getContext().setAuthentication(authentication);

// //         // Get user role
// //         String role = authentication.getAuthorities().iterator().next().getAuthority();

// //         log.info("User [{}] logged in with role [{}]", numeroTel, role);

// //         // Redirect based on role (no 'ROLE_' prefix)
// //         if ("CLIENT".equals(role)) {
// //             return "redirect:/client";  // Redirect to client page
// //         } else if ("AGENT".equals(role)) {
// //             return "redirect:/agent";  // Redirect to agent page
// //         } else if ("ADMIN".equals(role)) {
// //             return "redirect:/admin";  // Redirect to admin page
// //         } else {
// //             return "redirect:/home";  // Default redirect
// //         }

// //     } catch (BadCredentialsException e) {
// //         log.error("Authentication failed for phone: {}", numeroTel, e);
// //         model.addAttribute("error", "Invalid phone number or password.");
// //         return "login";  // Stay on login page if authentication fails
// //     }
// // }
// @PostMapping("/login")
// public String login(@RequestParam String numeroTel, 
//                     @RequestParam String password, 
//                     Model model, 
//                     HttpSession session) {
    
//     log.debug("Tentative de connexion avec le téléphone : [{}]", numeroTel);
//     System.out.println("Attempting login with phone number: " + numeroTel); // Debug

//     try {
//         // Authentifier l'utilisateur
//         Authentication authentication = authenticationManager.authenticate(
//             new UsernamePasswordAuthenticationToken(numeroTel, password)
//         );
//         SecurityContextHolder.getContext().setAuthentication(authentication);

//         // Récupérer les détails de l'utilisateur authentifié
//         UserDetails userDetails = (UserDetails) authentication.getPrincipal();
//         String numero = userDetails.getUsername(); // numéroTel

//         System.out.println("Authenticated user phone number: " + numero); // Debug

//         // Récupérer l'utilisateur depuis la base de données
//         User user = userRepository.findByNumeroTel(numero)
//                 .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

//         // Stocker les détails de l'utilisateur dans la session
//         // Stocker les détails de l'utilisateur dans la session
//         session.setAttribute("userId", user.getId()); // Ajout de l'ID
//         session.setAttribute("username", user.getNom());
//         session.setAttribute("prenom", user.getPrenom());
//         session.setAttribute("numeroTel", user.getNumeroTel());
//         session.setAttribute("role", user.getRole().name());


//         log.info("Utilisateur [{}] connecté avec rôle [{}]", user.getNom(), user.getRole().name());
//         log.info("Nom stocké en session: {}", session.getAttribute("username"));

//         // Redirection en fonction du rôle
//         switch (user.getRole().name()) {
//             case "CLIENT":
//                 System.out.println("Redirecting to /client_home"); // Debug
//                 return "redirect:/client_home";  
//             case "AGENT":
//                 System.out.println("Redirecting to /agent"); // Debug
//                 return "redirect:/agent_home";  
//             case "ADMIN":
//                 System.out.println("Redirecting to /admin"); // Debug
//                 return "redirect:/admin";  
//             default:
//                 System.out.println("Redirecting to /home"); // Debug
//                 return "redirect:/home";  
//         }

//     } catch (BadCredentialsException e) {
//         log.error("Échec d'authentification pour le téléphone : {}", numeroTel, e);
//         System.out.println("Authentication failed for phone number: " + numeroTel); // Debug
//         model.addAttribute("error", "Numéro de téléphone ou mot de passe invalide.");
//         return "login";  
//     }
// }

//     @GetMapping("/home")
//     public String home() {
//         return "home"; // This corresponds to home.jsp
//     }

//     // @GetMapping("/client_home")
//     // public String clientHome(Model model, HttpSession session) {
//     //     // Replace the Optional<User> handling
//     //     String numeroTel = (String) session.getAttribute("numeroTel");
//     //     Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);
        
//     //     if (userOptional.isPresent()) {
//     //         User user = userOptional.get(); // Get the User object from Optional
//     //         model.addAttribute("user", user); // Add user to the model
//     //     } else {
//     //         model.addAttribute("user", null); // Handle the case where no user is found
//     //     }

//     //     return "client_home";
//     // }

//     @GetMapping("/client_home")
//     public String clientHome(Model model, HttpSession session) {

//         // Get the current authentication object
//         Authentication auth = SecurityContextHolder.getContext().getAuthentication();

//         String numeroTel;

//         // Check if the user is authenticated and extract the phone number
//         if (auth != null && auth.getPrincipal() instanceof UserDetails) {
//             numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
//             model.addAttribute("numeroTel", numeroTel);
//         } else {
//             numeroTel = (String) session.getAttribute("numeroTel");
//             model.addAttribute("numeroTel", numeroTel != null ? numeroTel : "Non connecté");
//         }

//         // String numeroTel = (String) session.getAttribute("numeroTel");

//         Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);
//         userOptional.ifPresent(user -> model.addAttribute("user", user));

//         return "client_home";
//     }

//     @GetMapping("/logout")
//     public String logout(HttpServletRequest request, HttpServletResponse response) {
//         SecurityContextHolder.clearContext();  // Clear the security context
//         request.getSession().invalidate();  // Invalidate the session
//         return "redirect:/";  // Redirect to the home page
//     }




// // Load the admin page with users, services, and locations
// @GetMapping("/admin_users")
// public String create_user_page(Model model) {
//     List<User> admins = userRepository.findByRole(Role.ADMIN);
//     List<User> agents = userRepository.findByRole(Role.AGENT);
//     List<User> clients = userRepository.findByRole(Role.CLIENT);
//     List<OKService> services = serviceRepository.findAll();
//     List<Location> locations = locationRepository.findAll();

//     model.addAttribute("admins", admins);
//     model.addAttribute("agents", agents);
//     model.addAttribute("clients", clients);
//     model.addAttribute("services", services);
//     model.addAttribute("locations", locations);

//     return "admin_users"; // Loads create_user.jsp
// }

// // Handle user creation
// @PostMapping("/createUser")
// public String createUser(
//         @RequestParam String prenom,
//         @RequestParam String nom,
//         @RequestParam String numeroTel,
//         @RequestParam String password,
//         @RequestParam Role role,
//         @RequestParam(required = false) int serviceId,
//         @RequestParam(required = false) int locationId,
//         RedirectAttributes redirectAttributes
// ) {
//     // Hash the password
//     String hashedPassword = passwordEncoder.encode(password);

//     // Create a new user
//     User newUser = new User();
//     newUser.setPrenom(prenom);
//     newUser.setNom(nom);
//     newUser.setNumeroTel(numeroTel);
//     newUser.setPassword(hashedPassword);
//     newUser.setRole(role);

//     // If the user is an agent, assign service & location
//     if (role == Role.AGENT) {
//         Optional<OKService> service = serviceRepository.findById(serviceId);
//         Optional<Location> location = locationRepository.findById(locationId);
//         service.ifPresent(newUser::setService);
//         location.ifPresent(newUser::setLocation);
//     }

//     // Save user
//     userRepository.save(newUser);

//     // Get updated lists of users and other necessary data
//     List<User> admins = userRepository.findByRole(Role.ADMIN);
//     List<User> agents = userRepository.findByRole(Role.AGENT);
//     List<User> clients = userRepository.findByRole(Role.CLIENT);
//     List<OKService> services = serviceRepository.findAll();
//     List<Location> locations = locationRepository.findAll();

//     // Add updated data to redirect attributes
//     redirectAttributes.addFlashAttribute("admins", admins);
//     redirectAttributes.addFlashAttribute("agents", agents);
//     redirectAttributes.addFlashAttribute("clients", clients);
//     redirectAttributes.addFlashAttribute("services", services);
//     redirectAttributes.addFlashAttribute("locations", locations);

//     // Redirect back to the create_user page
//     return "redirect:/admin_users";
// }


// // Controller to handle user deletion
// @GetMapping("/deleteUser/{id}")
// public String deleteUser(@PathVariable("id") int id, Model model) {
//     // Delete the user by ID
//     userRepository.deleteById(id);

//     // Fetch updated data after deletion
//     List<User> admins = userRepository.findByRole(Role.ADMIN);
//     List<User> agents = userRepository.findByRole(Role.AGENT);
//     List<User> clients = userRepository.findByRole(Role.CLIENT);
//     List<OKService> services = serviceRepository.findAll();
//     List<Location> locations = locationRepository.findAll();

//     // Add attributes to the model for rendering
//     model.addAttribute("admins", admins);
//     model.addAttribute("agents", agents);
//     model.addAttribute("clients", clients);
//     model.addAttribute("services", services);
//     model.addAttribute("locations", locations);

//     // Redirect to the admin page
//     return "redirect:/admin_users";
// }




//     @GetMapping("/client_obtain_ticket")
//     public String clientObtainTicketPage(Model model) {
//         try {
//             List<OKService> services = gestionFileService.getAllServices();
//             List<Location> locations = gestionFileService.getAllLocations();

//             if (services == null || locations == null) {
//                 log.error("Donnees {Services ou localisations} sont null.");
//                 throw new IllegalStateException("Donnees {Services ou localisations} sont indisponibles.");
//             }

//             model.addAttribute("services", services);
//             model.addAttribute("locations", locations);
//             return "client_obtain_ticket";
//         } catch (Exception e) {
//             log.error("Error in clientPage method: {}", e.getMessage());
//             e.printStackTrace();
//             model.addAttribute("error", "Erreurs lors de la recup des services et localisations.");
//             return "error"; 
//         }
//     }

//     // @GetMapping("/client_view_tickets")
//     // public String clientViewTicketsPage(Model model) {
//     //     try {
//     //         List<OKService> services = gestionFileService.getAllServices();
//     //         List<Location> locations = gestionFileService.getAllLocations();

//     //         if (services == null || locations == null) {
//     //             log.error("Donnees {Services ou localisations} sont null.");
//     //             throw new IllegalStateException("Donnees {Services ou localisations} sont indisponibles.");
//     //         }

//     //         model.addAttribute("services", services);
//     //         model.addAttribute("locations", locations);
//     //         return "client_view_tickets";
//     //     } catch (Exception e) {
//     //         log.error("Error in clientPage method: {}", e.getMessage());
//     //         e.printStackTrace();
//     //         model.addAttribute("error", "Erreurs lors de la recup des services et localisations.");
//     //         return "error"; 
//     //     }
//     // }

//     @GetMapping("/client_view_tickets")
//     public String clientViewTicketsPage(Model model, HttpSession session) {
//         try {

//             // Get the current authentication object
//             Authentication auth = SecurityContextHolder.getContext().getAuthentication();

//             String numeroTel;

//             // Check if the user is authenticated and extract the phone number
//             if (auth != null && auth.getPrincipal() instanceof UserDetails) {
//                 numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
//                 model.addAttribute("numeroTel", numeroTel);
//             } else {
//                 numeroTel = (String) session.getAttribute("numeroTel");
//                 model.addAttribute("numeroTel", numeroTel != null ? numeroTel : "Non connecté");
//             }

//             // Récupérer l'utilisateur depuis la base de données
//             User user = userRepository.findByNumeroTel(numeroTel)
//                     .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

//             // Get the user ID from the session
//             Long userIdLong = (Long) user.getId(); // Assuming the user ID is stored in the session

//             if (userIdLong == null) {
//                 model.addAttribute("error", "User not logged in.");
//                 return "error"; // Redirect or show an error page
//             }

//             // Convert Long to int
//             int userId = userIdLong.intValue(); // Convert Long to int


//             // Fetch tickets related to the user
//             List<Ticket> tickets = ticketRepository.findByUserId(userId); // Assuming you have a method to find tickets by user ID
//             model.addAttribute("tickets", tickets);

//             // Fetch services and locations
//             List<OKService> services = gestionFileService.getAllServices();
//             List<Location> locations = gestionFileService.getAllLocations();

//             if (services == null || locations == null) {
//                 log.error("Data {Services or locations} are null.");
//                 throw new IllegalStateException("Data {Services or locations} are unavailable.");
//             }

//             // Add services and locations to the model
//             model.addAttribute("services", services);
//             model.addAttribute("locations", locations);

//             return "client_view_tickets"; // Return the view

//         } catch (Exception e) {
//             log.error("Error in clientViewTicketsPage method: {}", e.getMessage());
//             e.printStackTrace();
//             model.addAttribute("error", "Error retrieving services, locations, or tickets.");
//             return "error"; // Redirect or show an error page
//         }
//     }


//     @GetMapping("/client")
//     public String clientPage(Model model) {
//         try {
//             List<OKService> services = gestionFileService.getAllServices();
//             List<Location> locations = gestionFileService.getAllLocations();

//             if (services == null || locations == null) {
//                 log.error("Donnees {Services ou localisations} sont null.");
//                 throw new IllegalStateException("Donnees {Services ou localisations} sont indisponibles.");
//             }

//             model.addAttribute("services", services);
//             model.addAttribute("locations", locations);
//             return "client";
//         } catch (Exception e) {
//             log.error("Error in clientPage method: {}", e.getMessage());
//             e.printStackTrace();
//             model.addAttribute("error", "Erreurs lors de la recup des services et localisations.");
//             return "error"; 
//         }
//     }

//     @PostMapping("/client_ticket")
//     public String createTicket(@RequestParam int serviceId, @RequestParam int locationId, Model model, HttpSession session) {
//         try {

//             // Get the current authentication object
//             Authentication auth = SecurityContextHolder.getContext().getAuthentication();

//             String numeroTel;

//             // Check if the user is authenticated and extract the phone number
//             if (auth != null && auth.getPrincipal() instanceof UserDetails) {
//                 numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
//                 model.addAttribute("numeroTel", numeroTel);
//             } else {
//                 numeroTel = (String) session.getAttribute("numeroTel");
//                 model.addAttribute("numeroTel", numeroTel != null ? numeroTel : "Non connecté");
//             }

//             // Récupérer l'utilisateur depuis la base de données
//             User user = userRepository.findByNumeroTel(numeroTel)
//                     .orElseThrow(() -> new UsernameNotFoundException("Utilisateur introuvable"));

//             OKService service = gestionFileService.getServiceById(serviceId)
//                     .orElseThrow(() -> new IllegalArgumentException("Invalid service ID"));
//             Location location = gestionFileService.getLocationById(locationId)
//                     .orElseThrow(() -> new IllegalArgumentException("Invalid location ID"));

            

//             // creation du new ticket
//             Ticket newTicket = gestionFileService.createTicket(service, location, user);

//             // Ticket en cours
//             Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
//             Ticket currentTicket = currentTicketOptional.orElse(null);

//             // Calcul du nombre de personnes devant
//             int peopleAhead = gestionFileService.getPeopleAhead(newTicket.getId(), serviceId, locationId);

//             model.addAttribute("newTicket", newTicket);
//             model.addAttribute("currentTicket", currentTicket);
//             model.addAttribute("service", service);
//             model.addAttribute("location", location);
//             model.addAttribute("peopleAhead", peopleAhead);

//             return "client_ticket";
//         } catch (Exception e) {
//             log.error("Error creating ticket: {}", e.getMessage());
//             model.addAttribute("error", "There was an error creating the ticket.");
//             return "error";
//         }
//     }

//     @GetMapping("/agent/ticket/status")
// public String updateTicketStatus(@RequestParam(required = false) Integer ticketId,
//                                  @RequestParam(required = false) Integer serviceId,
//                                  @RequestParam(required = false) Integer locationId,
//                                  @RequestParam String action,
//                                  Model model, HttpSession session) {

//     // Retrieve user details from session (number and service)
//     String numeroTel = null;

//     Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//     if (auth != null && auth.getPrincipal() instanceof UserDetails) {
//         numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
//     } else {
//         numeroTel = (String) session.getAttribute("numeroTel");
//     }

//     Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);
//     if (!userOptional.isPresent()) {
//         model.addAttribute("error", "User not found.");
//         return "error"; // User not found
//     }

//     User user = userOptional.get();
//     locationId = locationId == null ? user.getLocationId() : locationId;
//     serviceId = serviceId == null ? user.getServiceId() : serviceId;

//     // Validate that all required parameters are present
//     if (ticketId == null || ticketId == 0) {
//         model.addAttribute("error", "Missing ticket ID.");
//         return "error"; // Return to error page if parameters are missing
//     }

//     try {
//         // Update ticket status
//         gestionFileService.updateTicketStatus(ticketId, action);

//         // Fetch the updated tickets list for the UI
//         List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
//         Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
//         Ticket currentTicket = currentTicketOptional.orElse(null);

//         // Add the updated data to the model
//         model.addAttribute("tickets", tickets);
//         model.addAttribute("currentTicket", currentTicket);
//         model.addAttribute("serviceId", serviceId);
//         model.addAttribute("locationId", locationId);
//         model.addAttribute("user", user);

//         return "agent_home"; // Return to agent page with updated ticket list
//     } catch (Exception e) {
//         log.error("Error updating ticket status: {}", e.getMessage());
//         model.addAttribute("error", "Unable to update ticket status: " + e.getMessage());
//         return "error"; // Handle errors gracefully
//     }
// }


// // @GetMapping("/agent/ticket/status")
// // public String updateTicketStatus(@RequestParam(required = false) Integer ticketId,
// //                                  @RequestParam(required = false) Integer serviceId,
// //                                  @RequestParam(required = false) Integer locationId,
// //                                  @RequestParam String action,
// //                                  Model model) {

// //     // Validate that all required parameters are present
// //     if (ticketId == null || serviceId == null || locationId == null || ticketId == 0) {
// //         model.addAttribute("error", "Missing required parameters.");
// //         return "error"; // Return to error page if parameters are missing
// //     }

// //     try {
// //         // Update ticket status
// //         gestionFileService.updateTicketStatus(ticketId, action);

// //         // Fetch the updated tickets list for the UI
// //         List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
// //         Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
// //         Ticket currentTicket = currentTicketOptional.orElse(null);

// //         // Add the updated data to the model
// //         model.addAttribute("tickets", tickets);
// //         model.addAttribute("currentTicket", currentTicket);
// //         model.addAttribute("serviceId", serviceId);
// //         model.addAttribute("locationId", locationId);

// //         return "agent_home"; // Return to agent page with updated ticket list
// //     } catch (Exception e) {
// //         log.error("Error updating ticket status: {}", e.getMessage());
// //         model.addAttribute("error", "Unable to update ticket status: " + e.getMessage());
// //         return "error"; // Handle errors gracefully
// //     }
// // }

// // agent

// @GetMapping("/agent")
// public String agentPage(Model model) {
//     model.addAttribute("services", gestionFileService.getAllServices());
//     model.addAttribute("locations", gestionFileService.getAllLocations());
//     return "agent";
// }

// @GetMapping("/agent_home")
// public String agentHomePage(Model model, HttpSession session) {
//     // Get the current authentication object
//     Authentication auth = SecurityContextHolder.getContext().getAuthentication();

//     String numeroTel = null;

//     // Check if the user is authenticated and extract the phone number
//     if (auth != null && auth.getPrincipal() instanceof UserDetails) {
//         numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
//     } else {
//         numeroTel = (String) session.getAttribute("numeroTel");
//     }

//     model.addAttribute("numeroTel", numeroTel != null ? numeroTel : "Non connecté");

//     // Retrieve user details from the database
//     Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);

//     if (userOptional.isPresent()) {
//         User user = userOptional.get();
//         Integer locationId = user.getLocationId();
//         Integer serviceId = user.getServiceId();

//         model.addAttribute("user", user);
//         model.addAttribute("locationId", locationId);
//         model.addAttribute("serviceId", serviceId);

//         // Fetch tickets based on service and location
//         List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
//         Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
//         Ticket currentTicket = currentTicketOptional.orElse(null);

//         model.addAttribute("tickets", tickets);
//         model.addAttribute("currentTicket", currentTicket);
//     }

//     // Fetch and add services and locations to the model
//     model.addAttribute("services", gestionFileService.getAllServices());
//     model.addAttribute("locations", gestionFileService.getAllLocations());

//     return "agent_home";
// }


// @GetMapping("/agent/tickets")
// public String viewTickets(@RequestParam(required = false) Integer serviceId,
//                           @RequestParam(required = false) Integer locationId, 
//                           Model model) {
//     if (serviceId == null || locationId == null) {
//         log.warn("Missing serviceId or locationId");
//         model.addAttribute("error", "Please select both a service and a location.");
//         model.addAttribute("services", gestionFileService.getAllServices());
//         model.addAttribute("locations", gestionFileService.getAllLocations());
//         return "agent";
//     }
//     // Proceed with fetching tickets
//     List<Ticket> tickets = gestionFileService.getTicketsByServiceAndLocation(serviceId, locationId);
//     Optional<Ticket> currentTicketOptional = gestionFileService.getCurrentTicket(serviceId, locationId);
//     Ticket currentTicket = currentTicketOptional.orElse(null);

//     model.addAttribute("tickets", tickets);
//     model.addAttribute("currentTicket", currentTicket); 
//     model.addAttribute("services", gestionFileService.getAllServices());
//     model.addAttribute("locations", gestionFileService.getAllLocations());

//     return "agent";
// }

// @GetMapping("/ticket/{ticketId}")
// public String viewTicket(@PathVariable int ticketId, Model model) {
//     Ticket ticket = ticketRepository.findById(ticketId)
//             .orElseThrow(() -> new IllegalArgumentException("Invalid ticket ID"));

//     Optional<Ticket> currentTicket = gestionFileService.getCurrentTicket(ticket.getService().getId(), ticket.getLocation().getId());

//     model.addAttribute("ticket", ticket);
//     model.addAttribute("currentTicket", currentTicket.orElse(null)); // Pass null if no ticket is found
//     return "ticket";
// }

// // admin
// @GetMapping("/admin")
// public String adminBackoffice(Model model) {
//     // Retrieve all services and locations
//     List<OKService> services = gestionFileService.getAllServices();
//     List<Location> locations = gestionFileService.getAllLocations();

//     model.addAttribute("services", services);
//     model.addAttribute("locations", locations);

//     // Prepare a list to hold QueueInfo objects
//     List<QueueInfo> queueInfos = new ArrayList<>();

//     for (OKService service : services) {
//         for (Location location : locations) {
//             // Retrieve queue information for the given service and location
//             QueueInfo queueInfo = gestionFileService.getQueueInfo(service, location);
//             if (queueInfo != null) {
//                 queueInfos.add(queueInfo);
//             }
//         }
//     }

//     model.addAttribute("queueInfos", queueInfos);

//     return "admin";
// }


// @GetMapping("/admin_home")
// public String adminHomePage(Model model, HttpSession session) {
//     // Get the current authentication object
//     Authentication auth = SecurityContextHolder.getContext().getAuthentication();

//     String numeroTel = null;

//     // Check if the user is authenticated and extract the phone number
//     if (auth != null && auth.getPrincipal() instanceof UserDetails) {
//         numeroTel = ((UserDetails) auth.getPrincipal()).getUsername();
//     } else {
//         numeroTel = (String) session.getAttribute("numeroTel");
//     }

//     model.addAttribute("numeroTel", numeroTel != null ? numeroTel : "Non connecté");

//     // Retrieve user details from the database
//     Optional<User> userOptional = userRepository.findByNumeroTel(numeroTel);

//     if (userOptional.isPresent()) {
//         User user = userOptional.get();

//         model.addAttribute("user", user);
//     }

//     // Retrieve all services and locations
//     List<OKService> services = gestionFileService.getAllServices();
//     List<Location> locations = gestionFileService.getAllLocations();

//     // Fetch and add services and locations to the model
//     model.addAttribute("services", gestionFileService.getAllServices());
//     model.addAttribute("locations", gestionFileService.getAllLocations());

//     // Prepare a list to hold QueueInfo objects
//     List<QueueInfo> queueInfos = new ArrayList<>();

//     for (OKService service : services) {
//         for (Location location : locations) {
//             // Retrieve queue information for the given service and location
//             QueueInfo queueInfo = gestionFileService.getQueueInfo(service, location);
//             if (queueInfo != null) {
//                 queueInfos.add(queueInfo);
//             }
//         }
//     }

//     model.addAttribute("queueInfos", queueInfos);

//     return "admin_home";
// }




// }
