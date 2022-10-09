
use cursive::{Cursive, CursiveRunnable};
use cursive::event::Event;
use cursive::reexports::crossbeam_channel::Sender;
use cursive::traits::{Nameable, Scrollable};
use cursive::view::ScrollStrategy;
use cursive::views::{TextView, LinearLayout, Panel, ResizedView, Dialog};

// TODO: to make the tui optional I'm using the used bool. This means that the structure
// TODO: gets created anyway. Should try to find a way to handle this with an Option in main
pub struct Tui {
    siv: CursiveRunnable,
    used: bool
}

impl Tui {
    pub fn new(used: bool) -> Self {
        let mut siv = cursive::default();
        if used {
            siv.add_global_callback('q', |s| Self::quit_dialog(s));
        }
        Self { siv, used }
    }

    pub fn draw(&mut self) {
        self.siv.add_fullscreen_layer(
        ResizedView::with_full_screen(
                LinearLayout::vertical().child(
                    Panel::new(
                        TextView::new("")
                            .with_name("main")
                            .scrollable()
                            .scroll_strategy(ScrollStrategy::StickToBottom)
                    )
                ).child(
                    Panel::new(
                        TextView::new("Press q to quit.").with_name("info")
                    )
                )
            )
        );
    }

    pub fn add_global_callback<F, E: Into<Event>>(&mut self, e: Event, cb: F)
    where
        F: FnMut(&mut Cursive) + 'static {
        self.siv.add_global_callback(e, cb);
    }

    pub fn run(&mut self) {
        self.siv.run();
    }

    // TODO: Check sender type (mpsc or crossbeam)
    pub fn get_cloned_sink(&self) -> Sender<Box<dyn FnOnce(&mut Cursive)+Send>> {
        self.siv.cb_sink().clone()
    }

    fn quit_dialog(siv: &mut Cursive) {
        siv.add_layer(Dialog::around(TextView::new("Do you really want to stop the sniffing?"))
            .title("Exit?")
            .button("Quit", |s| s.quit())
            .button("Cancel", |s| { s.pop_layer(); })
        );
    }

    pub fn append_to_TextView(siv: &mut Cursive, name: &str, str_to_append: String) {
        let mut view = siv.find_name::<TextView>(name).unwrap();
        view.append(str_to_append);
    }

    pub fn is_used(&self) -> bool {
        self.used
    }

}
