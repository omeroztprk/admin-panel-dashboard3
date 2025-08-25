import { Component, OnInit, Input } from '@angular/core';

@Component({
  selector: 'app-footer',
  templateUrl: './footer.component.html',
  styleUrls: ['./footer.component.scss']
})
export class FooterComponent implements OnInit {
  @Input() showLinks = true;
  @Input() showBuildInfo = false;
  @Input() isMinimal = false;

  currentYear = new Date().getFullYear();
  version = '1.0.0';
  buildDate = new Date().toLocaleDateString('tr-TR');
  isOnline = navigator.onLine;

  ngOnInit() {
    // Monitor online status
    window.addEventListener('online', () => this.isOnline = true);
    window.addEventListener('offline', () => this.isOnline = false);
  }
}