import {Component} from '@angular/core';
import {Credentials} from '../shared';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss']
})
export class LoginComponent {

  credentials = <Credentials>{username: null, password: null};

  constructor() { }

  login() {

  }
}
