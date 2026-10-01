package com.maovares.ms_products;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class ClientCertFilter extends OncePerRequestFilter {

    @Value("${CLIENT_CERT_THUMBPRINT:}")
    private String expectedThumbprint;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Parte 1: leer el header que envía Azure App Service
        String header = request.getHeader("X-ARR-ClientCert");
        if (header == null || header.isBlank()) {
            deny(response, "Client Certificate Required");
            return;
        }

        try {
            // Parte 2: convertir el Base64 a X509Certificate
            byte[] der = Base64.getDecoder().decode(header);
            X509Certificate cert = (X509Certificate) CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));

            // Parte 3: calcular el thumbprint SHA-1 del certificado recibido
            byte[] hash = MessageDigest.getInstance("SHA-1").digest(cert.getEncoded());
            String thumbprint = HexFormat.of().withUpperCase().formatHex(hash);

            // Parte 4: comparar con el thumbprint esperado
            String expected = expectedThumbprint.replace(":", "").trim();
            if (!thumbprint.equalsIgnoreCase(expected)) {
                deny(response, "Invalid Client Certificate");
                return;
            }

            chain.doFilter(request, response);
        } catch (Exception e) {
            deny(response, "Invalid Client Certificate");
        }
    }

    private void deny(HttpServletResponse response, String msg) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("text/html");
        response.getWriter().write("<html><body><h1>" + msg + "</h1></body></html>");
    }
}