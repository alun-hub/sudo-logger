declare module 'asciinema-player' {
  export interface Player {
    dispose(): void;
    getCurrentTime(): number;
    getDuration(): number;
    play(): void;
    pause(): void;
    seek(time: number): void;
  }

  export interface PlayerOptions {
    cols?: number;
    rows?: number;
    autoPlay?: boolean;
    preload?: boolean;
    loop?: boolean | number;
    speed?: number;
    startAt?: number;
    poster?: string;
    markers?: any[];
    idleTimeLimit?: number;
    theme?: string;
    terminalFontSize?: string;
    terminalFontFamily?: string;
    terminalLineHeight?: number;
    fit?: 'width' | 'height' | 'both' | false;
    controls?: boolean;
    title?: string;
    author?: string;
    authorURL?: string;
    authorImgURL?: string;
  }

  export function create(
    src: string | { data: any } | File | Blob,
    container: HTMLElement,
    options?: PlayerOptions
  ): Player;
}
