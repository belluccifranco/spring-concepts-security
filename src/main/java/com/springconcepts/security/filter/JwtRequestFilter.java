package com.springconcepts.security.filter;

import com.springconcepts.security.service.UserService;
import com.springconcepts.security.util.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

  private final UserService userService;
  private final JwtTokenUtil jwtTokenUtil;
  private static final String AUTHORIZATION_HEADER = "Authorization";
  private static final String BEARER = "Bearer ";

  @Autowired
  public JwtRequestFilter(UserService userService, JwtTokenUtil jwtTokenUtil) {
    this.userService = userService;
    this.jwtTokenUtil = jwtTokenUtil;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse,
      FilterChain filterChain)
      throws ServletException, IOException {

    final String authorizationHeader = httpServletRequest.getHeader(AUTHORIZATION_HEADER);
    String username = null;
    String jwt = null;
    if (authorizationHeader != null && authorizationHeader.startsWith(BEARER)) {
      jwt = authorizationHeader.substring(7);
      username = jwtTokenUtil.extractUsername(jwt);
    }
    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = userService.loadUserByUsername(username);
      boolean isValid = jwtTokenUtil.validateToken(jwt, userDetails);
      if (isValid) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
      }
    }
    filterChain.doFilter(httpServletRequest, httpServletResponse);
  }
}
