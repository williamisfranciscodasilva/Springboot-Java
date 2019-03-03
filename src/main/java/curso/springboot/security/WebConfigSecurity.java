package curso.springboot.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class WebConfigSecurity extends WebSecurityConfigurerAdapter{
	
	@Override // Configura as solicitações de acesso por http
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf()
		.disable() // desativa configurações padrão de memória.
		.authorizeRequests() // permitir retringir acessos.
		.antMatchers(HttpMethod.GET, "/").permitAll() // qualquer usuário acessa a página inicial.
		.anyRequest().authenticated()
		.and().formLogin().permitAll() // permite qualquer usuário
		.and().logout() // mapeia a url de sair do sistema e invalida usuário autenticado
		.logoutRequestMatcher(new AntPathRequestMatcher("/logout"));
	}
	
	@Override // cria autenticação do usuário com o banco de dados ou em memória
	protected void configure(AuthenticationManagerBuilder auth) throws Exception{
		
		auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
		.withUser("alex")
		.password("$2a$10$j1cImW9LM8tNLvkPONuTLuW6UalvSjUWVfHskoJ5HqscM07dRgqpi")
		.roles("ADMIN");
	}
	
	@Override // Ignora url especificas
	public void configure(WebSecurity web) throws Exception{
		
		web.ignoring().antMatchers("/materialize/**");
	}
}
