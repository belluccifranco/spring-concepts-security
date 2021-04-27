package com.springconcepts.security.controller;

import com.springconcepts.security.model.AuthenticationRequest;
import com.springconcepts.security.service.UserService;
import com.springconcepts.security.util.JwtTokenUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Slf4j
public class HomeController {

  private final AuthenticationManager authenticationManager;
  private final UserService userService;
  private final JwtTokenUtil jwtTokenUtil;

  @Autowired
  public HomeController(
      AuthenticationManager authenticationManager,
      UserService userService,
      JwtTokenUtil jwtTokenUtil) {
    this.authenticationManager = authenticationManager;
    this.userService = userService;
    this.jwtTokenUtil = jwtTokenUtil;
  }

  @GetMapping("/hello")
  @PreAuthorize("hasRole('ADMIN')")
  public String hello(Authentication authentication) {
    return authentication.getName();
  }

  @PostMapping("/authenticate")
  public ResponseEntity<String> authenticate(
      @RequestBody AuthenticationRequest authenticationRequest) {
    try {
      authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(
              authenticationRequest.getUsername(), authenticationRequest.getPassword()));
    } catch (BadCredentialsException ex) {
      log.error(ex.getMessage());
      throw ex;
    }
    UserDetails userDetails = userService.loadUserByUsername(authenticationRequest.getUsername());
    String jwt = jwtTokenUtil.generateToken(userDetails);
    return ResponseEntity.ok(jwt);
  }
}
