package sn.ousoka.GestionFile;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Component
public class TabAwareSecurityContextRepository extends HttpSessionSecurityContextRepository {

    private static final String SECURITY_CONTEXT_ATTRIBUTE_PREFIX = "SPRING_SECURITY_CONTEXT_";

    @Override
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        String tabId = request.getHeader("X-Tab-ID");
        if (tabId == null || tabId.isEmpty()) {
            return super.loadContext(requestResponseHolder);
        }

        HttpSession session = request.getSession(false);
        if (session != null) {
            String sessionKey = SECURITY_CONTEXT_ATTRIBUTE_PREFIX + tabId;
            SecurityContext context = (SecurityContext) session.getAttribute(sessionKey);
            if (context != null) {
                return context;
            }
        }
        return SecurityContextHolder.createEmptyContext();
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
        String tabId = request.getHeader("X-Tab-ID");
        if (tabId == null || tabId.isEmpty()) {
            super.saveContext(context, request, response);
            return;
        }

        HttpSession session = request.getSession(true);
        String sessionKey = SECURITY_CONTEXT_ATTRIBUTE_PREFIX + tabId;
        session.setAttribute(sessionKey, context);
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        String tabId = request.getHeader("X-Tab-ID");
        if (tabId == null || tabId.isEmpty()) {
            return super.containsContext(request);
        }

        HttpSession session = request.getSession(false);
        return session != null && session.getAttribute(SECURITY_CONTEXT_ATTRIBUTE_PREFIX + tabId) != null;
    }
}