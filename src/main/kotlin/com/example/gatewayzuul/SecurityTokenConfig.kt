package com.example.gatewayzuul

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@EnableWebSecurity // Enable security config. This annotation denotes config for spring security.
class SecurityTokenConfig : WebSecurityConfigurerAdapter() {
    @Autowired
    private val jwtConfig: JwtConfig? = null

    @Throws(Exception::class)
    override fun configure(http: HttpSecurity) {
        http
                .csrf().disable()
                // make sure we use stateless session; session won't be used to store user's state.
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // handle an authorized attempts
                .exceptionHandling().authenticationEntryPoint { req: HttpServletRequest?, rsp: HttpServletResponse, e: AuthenticationException? -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED) }
                .and()
                // Add a filter to validate the tokens with every request
                .addFilterAfter(jwtConfig?.let { JwtTokenAuthenticationFilter(it) }, UsernamePasswordAuthenticationFilter::class.java)
                // authorization requests config
                .authorizeRequests()
                // allow all who are accessing "auth" service
                .antMatchers(HttpMethod.POST, jwtConfig!!.uri).permitAll()
                .antMatchers(HttpMethod.GET, "/user-service/status").authenticated()
                // must be an admin if trying to access admin area (authentication is also required here)
                .antMatchers("/form-service" + "/admin/**").hasRole("ADMIN")
                // Any other request must be authenticated
                .anyRequest().authenticated()

    }

    @Bean
    fun jwtConfig(): JwtConfig {
        return JwtConfig()
    }
}
