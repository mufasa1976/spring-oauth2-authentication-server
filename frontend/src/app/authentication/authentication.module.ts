import {NgModule} from '@angular/core';
import {CommonModule} from '@angular/common';
import {AuthenticationService} from './services/authentication.service';
import {LoginComponent} from './login/login.component';
import {ErrorStateMatcher, MatButtonModule, MatCardModule, MatInputModule, ShowOnDirtyErrorStateMatcher} from '@angular/material';
import {FormsModule} from '@angular/forms';

const declarations = [LoginComponent];

@NgModule({
  declarations: declarations,
  imports: [
    CommonModule,
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatInputModule
  ],
  exports: declarations,
  providers: [
    AuthenticationService,
    {provide: ErrorStateMatcher, useClass: ShowOnDirtyErrorStateMatcher}
  ]
})
export class AuthenticationModule {}
