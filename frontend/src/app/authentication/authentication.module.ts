import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {AuthenticationService} from './services/authentication.service';
import {LoginComponent} from './login/login.component';

const declarations = [LoginComponent];

@NgModule({
  declarations: declarations,
  imports: [
    CommonModule
  ],
  exports: declarations,
  providers: [
    AuthenticationService
  ]
})
export class AuthenticationModule {}
