package com.maria.t1_auth.filter;

import com.maria.t1_auth.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;


import java.io.IOException;
import java.util.List;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService svc;

    public JwtAuthFilter(JwtService svc){ this.svc=svc; }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        var hdr = req.getHeader("Authorization");
        if (hdr!=null && hdr.startsWith("Bearer ")) {
            try {
                var claims = svc.parseAccessToken(hdr.substring(7));
                var auth = new UsernamePasswordAuthenticationToken(
                        claims.getSubject(), null,
                        ((List<String>)claims.getClaim("role")).stream()
                                .map(SimpleGrantedAuthority::new).toList());
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                res.sendError(401,"Unauthorized");
                return;
            }
        }
        chain.doFilter(req,res);
    }
}
