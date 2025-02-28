package sn.ousoka.GestionFile;

import org.springframework.stereotype.Component;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class TabSessionFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String tabId = request.getHeader("X-Tab-ID");
        if (tabId != null && !tabId.isEmpty()) {
            HttpSession session = request.getSession(true); // Create session if needed
            String sessionKey = "tabSession_" + tabId;
            if (session.getAttribute(sessionKey) == null) {
                // Store tab-specific session ID or data
                session.setAttribute(sessionKey, tabId);
            }
        }
        filterChain.doFilter(request, response);
    }
}